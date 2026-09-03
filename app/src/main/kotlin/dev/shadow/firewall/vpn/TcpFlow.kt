package dev.shadow.firewall.vpn

import android.util.Log
import dev.shadow.firewall.core.FlowKey
import dev.shadow.firewall.core.PacketFactory
import dev.shadow.firewall.core.Socks5
import dev.shadow.firewall.core.Socks5Client
import dev.shadow.firewall.core.TcpFlags
import dev.shadow.firewall.core.TcpSegment
import dev.shadow.firewall.core.Tor
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.CancelledKeyException
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.security.SecureRandom
import java.util.ArrayDeque

/**
 * One TCP connection, bridged between the tun device and a real socket.
 *
 * The app on the device believes it is talking to the remote server; in reality it completes
 * a handshake with us, and we relay the bytes over a separate socket that is protected from
 * the VPN so it uses the underlying network.
 *
 * This is a deliberately small subset of TCP. There is no congestion control and no
 * retransmission toward the app, because the tun device is a local queue rather than a lossy
 * link: anything we hand to the kernel arrives. What it does implement is the handshake,
 * in-order data transfer, flow control in both directions, and orderly and abortive close.
 *
 * When [proxyAddress] is set the socket is opened to a SOCKS5 proxy instead of to the server,
 * and the app is not answered until the proxy confirms the connection. That ordering matters:
 * the app must never see a completed handshake for a connection the proxy went on to refuse,
 * or it would believe it was talking to the server when nothing was carrying its bytes.
 *
 * Every method that touches state is synchronised; the tunnel reader thread delivers segments
 * while the selector thread delivers socket readiness.
 */
class TcpFlow(
    val key: FlowKey,
    val eventId: Long,
    private val appAddress: InetAddress,
    private val appPort: Int,
    private val remoteAddress: InetAddress,
    private val remotePort: Int,
    private val tunMss: Int,
    private val sink: PacketSink,
    private val selectorLoop: SelectorLoop,
    private val onBytes: (sent: Long, received: Long) -> Unit,
    private val onClosed: (TcpFlow) -> Unit,
    /** A local SOCKS5 proxy to relay through, or null to dial the server directly. */
    private val proxyAddress: InetSocketAddress? = null,
) : SelectableFlow {

    enum class State { CONNECTING, PROXY, HANDSHAKE, ESTABLISHED, CLOSED }

    private val channel: SocketChannel = SocketChannel.open()
    private var selectionKey: SelectionKey? = null

    private var state = State.CONNECTING

    /**
     * The SOCKS conversation, when there is a proxy. Built here rather than passed in so the
     * request always describes this flow's own destination.
     */
    private val socks: Socks5Client? = proxyAddress?.let {
        Socks5Client(Socks5.connectRequest(remoteAddress.address, remotePort))
    }

    /** Handshake bytes still to be written to the proxy. */
    private var proxyOut: ByteBuffer? = null

    /**
     * Server bytes that arrived in the same read as the proxy's reply. Held until the app has
     * finished its handshake, because data sent before that has nowhere to be delivered.
     */
    private var earlyFromRemote: ByteArray? = null

    /** True when this flow is relayed through a proxy rather than dialled directly. */
    val isProxied: Boolean get() = socks != null

    /** How long this flow may sit unestablished before the sweeper gives up on it. */
    val handshakeTimeoutMillis: Long
        get() = if (isProxied) PROXY_HANDSHAKE_MILLIS else DIRECT_HANDSHAKE_MILLIS

    /** Next sequence number we will use when sending toward the app. */
    private var sendNext: Long = SecureRandom().nextInt().toLong() and 0xFFFFFFFFL

    /** Highest sequence number the app has acknowledged. */
    private var sendUnacked: Long = sendNext

    /** Next sequence number we expect to receive from the app. */
    private var recvNext: Long = 0

    /** The app's advertised receive window; how much we may have in flight toward it. */
    private var peerWindow: Int = DEFAULT_WINDOW

    /** Payload size we will not exceed when sending toward the app. */
    private var segmentSize: Int = tunMss

    private val pendingToRemote = ArrayDeque<ByteBuffer>()
    private var pendingBytes = 0

    private var finFromApp = false
    private var finToApp = false
    private var remoteReadsPaused = false

    private var bytesSent = 0L
    private var bytesReceived = 0L

    @Volatile
    var lastActivityMillis: Long = System.currentTimeMillis()
        private set

    val isClosed: Boolean get() = synchronized(this) { state == State.CLOSED }

    /** True once the app has completed the handshake, used to pick an idle timeout. */
    val isEstablished: Boolean get() = synchronized(this) { state == State.ESTABLISHED }

    /**
     * Starts the outbound connection in response to the app's SYN. The caller must already
     * have protected the socket from the VPN.
     */
    @Synchronized
    fun open(syn: TcpSegment, protect: (SocketChannel) -> Boolean) {
        recvNext = PacketFactory.nextSequence(syn.sequenceNumber, 1)
        peerWindow = syn.window.coerceAtLeast(1)
        // Never send the app a segment larger than it or the tunnel can take.
        segmentSize = minOf(tunMss, syn.maxSegmentSize ?: tunMss).coerceAtLeast(MIN_SEGMENT)

        try {
            channel.configureBlocking(false)
            channel.socket().tcpNoDelay = true
            // Without this the socket would be routed back into our own tunnel.
            if (!protect(channel)) {
                Log.w(TAG, "could not protect socket for $key")
                abort()
                return
            }
            channel.connect(proxyAddress ?: InetSocketAddress(remoteAddress, remotePort))
            selectorLoop.register(channel, SelectionKey.OP_CONNECT, this)
        } catch (error: IOException) {
            Log.d(TAG, "connect failed for $key: ${error.message}")
            abort()
        }
    }

    @Synchronized
    override fun onRegistered(registered: SelectionKey) {
        if (state == State.CLOSED) {
            registered.cancel()
            return
        }
        selectionKey = registered
    }

    /** Handles one segment the app sent into the tunnel. */
    @Synchronized
    fun onSegment(segment: TcpSegment) {
        if (state == State.CLOSED) return
        lastActivityMillis = System.currentTimeMillis()

        if (segment.isRst) {
            closeInternal(sendReset = false)
            return
        }

        // Mid-SOCKS-handshake the socket carries the proxy's conversation, not the app's, so
        // nothing from the app may be written to it yet. The app is still waiting on its SYN
        // and has nothing legitimate to say; a retransmitted SYN is answered once we are up.
        if (state == State.PROXY) return

        if (segment.isSyn && !segment.isAck) {
            // A retransmitted SYN: re-send our SYN/ACK if we already produced one.
            if (state == State.HANDSHAKE) sendSynAck()
            return
        }

        if (segment.isAck) {
            if (sequenceLessOrEqual(sendUnacked, segment.acknowledgementNumber) &&
                sequenceLessOrEqual(segment.acknowledgementNumber, sendNext)
            ) {
                sendUnacked = segment.acknowledgementNumber
            }
            peerWindow = segment.window.coerceAtLeast(1)
            if (state == State.HANDSHAKE) {
                state = State.ESTABLISHED
                flushEarlyFromRemote()
            }
            resumeRemoteReadsIfPossible()
        }

        val payloadLength = segment.payloadLength
        if (payloadLength > 0) {
            if (segment.sequenceNumber == recvNext) {
                queueToRemote(segment.packet.data, segment.payloadOffset, payloadLength)
                recvNext = PacketFactory.nextSequence(recvNext, payloadLength)
                bytesSent += payloadLength
                onBytes(bytesSent, bytesReceived)
                sendAck()
            } else {
                // Either a duplicate we already consumed or a gap we will not buffer.
                // Re-acknowledging tells the app exactly where to resume.
                sendAck()
            }
        }

        if (segment.isFin) {
            val finSequence = PacketFactory.nextSequence(segment.sequenceNumber, payloadLength)
            if (finSequence == recvNext) {
                recvNext = PacketFactory.nextSequence(recvNext, 1)
                finFromApp = true
                sendAck()
                shutdownRemoteOutputIfDrained()
            } else {
                sendAck()
            }
        }
    }

    /** Selector callback: the socket became connectable, readable or writable. */
    override fun onSelected(selected: SelectionKey) {
        synchronized(this) {
            if (state == State.CLOSED) return
            try {
                if (selected.isValid && selected.isConnectable) finishConnect(selected)
                if (state == State.PROXY) {
                    if (selected.isValid) serviceProxy(selected)
                    return
                }
                if (selected.isValid && selected.isWritable) drainToRemote(selected)
                if (selected.isValid && selected.isReadable) readFromRemote()
            } catch (error: IOException) {
                Log.d(TAG, "socket error on $key: ${error.message}")
                closeInternal(sendReset = true)
            }
        }
    }

    private fun finishConnect(key: SelectionKey) {
        if (!channel.finishConnect()) return

        val client = socks
        if (client != null) {
            // The app stays waiting on its SYN until the proxy says the connection is up.
            state = State.PROXY
            proxyOut = ByteBuffer.wrap(client.greeting())
            key.interestOps(SelectionKey.OP_READ or SelectionKey.OP_WRITE)
            return
        }

        key.interestOps(SelectionKey.OP_READ)
        answerAppSyn(key)
    }

    /** Completes the app's half of the handshake, once we know we have somewhere to relay to. */
    private fun answerAppSyn(key: SelectionKey) {
        sendSynAck()
        state = State.HANDSHAKE
        // A retransmitted SYN carrying data can queue bytes before the socket was ready.
        if (pendingToRemote.isNotEmpty()) drainToRemote(key)
    }

    // ---------------------------------------------------------------- socks

    /** Moves the SOCKS handshake forward by whatever the socket is ready for. */
    private fun serviceProxy(key: SelectionKey) {
        val client = socks ?: return
        if (!flushProxy(key)) return
        if (!key.isReadable) return

        val buffer = ByteArray(PROXY_BUFFER)
        val read = channel.read(ByteBuffer.wrap(buffer))
        if (read < 0) {
            failProxy("the proxy closed the connection")
            return
        }
        if (read == 0) return
        lastActivityMillis = System.currentTimeMillis()

        when (val step = client.onBytes(buffer, 0, read)) {
            is Socks5Client.Step.NeedMore -> Unit
            is Socks5Client.Step.Send -> {
                proxyOut = ByteBuffer.wrap(step.bytes)
                flushProxy(key)
            }
            is Socks5Client.Step.Ready -> {
                earlyFromRemote = step.earlyData.takeIf { it.isNotEmpty() }
                key.interestOps(SelectionKey.OP_READ)
                answerAppSyn(key)
            }
            is Socks5Client.Step.Failed -> failProxy(step.reason)
        }
    }

    /** Returns true once nothing is left to write to the proxy. */
    private fun flushProxy(key: SelectionKey): Boolean {
        val out = proxyOut ?: return true
        channel.write(out)
        if (out.hasRemaining()) {
            key.interestOps(SelectionKey.OP_READ or SelectionKey.OP_WRITE)
            return false
        }
        proxyOut = null
        key.interestOps(SelectionKey.OP_READ)
        return true
    }

    private fun failProxy(reason: String) {
        Log.d(TAG, "proxy refused $key: $reason")
        // Resetting is the only correct answer: the app is still waiting on its SYN, and
        // there is deliberately no direct fallback for a connection the user asked to route.
        closeInternal(sendReset = true)
    }

    /**
     * Delivers anything the server sent before the app finished its handshake. Chunked to the
     * negotiated segment size, since nothing else has bounded it.
     */
    private fun flushEarlyFromRemote() {
        val early = earlyFromRemote ?: return
        earlyFromRemote = null
        var offset = 0
        while (offset < early.size) {
            val size = minOf(segmentSize, early.size - offset)
            emit(
                flags = TcpFlags.PSH or TcpFlags.ACK,
                sequenceNumber = sendNext,
                payload = early.copyOfRange(offset, offset + size),
            )
            sendNext = PacketFactory.nextSequence(sendNext, size)
            bytesReceived += size
            offset += size
        }
        onBytes(bytesSent, bytesReceived)
    }

    private fun sendSynAck() {
        emit(
            flags = TcpFlags.SYN or TcpFlags.ACK,
            sequenceNumber = sendUnacked,
            mss = segmentSize,
        )
        // The SYN itself consumes one sequence number.
        if (sendNext == sendUnacked) sendNext = PacketFactory.nextSequence(sendNext, 1)
    }

    private fun sendAck() {
        emit(flags = TcpFlags.ACK, sequenceNumber = sendNext)
    }

    private fun queueToRemote(data: ByteArray, offset: Int, length: Int) {
        pendingToRemote.addLast(ByteBuffer.wrap(data.copyOfRange(offset, offset + length)))
        pendingBytes += length
        // Before the socket finishes connecting there is no key yet; finishConnect drains.
        val key = selectionKey ?: return
        try {
            drainToRemote(key)
            // interestOps may have changed from a thread that is not the selector thread.
            selectorLoop.wakeup()
        } catch (error: IOException) {
            closeInternal(sendReset = true)
        } catch (ignored: CancelledKeyException) {
            closeInternal(sendReset = false)
        }
    }

    private fun drainToRemote(key: SelectionKey) {
        while (true) {
            // peekFirst rather than first(): on newer platforms ArrayDeque also exposes a
            // getFirst() that Kotlin sees as a property, making first() ambiguous.
            val buffer = pendingToRemote.peekFirst() ?: break
            val written = channel.write(buffer)
            pendingBytes -= written
            if (buffer.hasRemaining()) {
                // Socket send buffer is full; finish when it drains.
                key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
                return
            }
            pendingToRemote.removeFirst()
        }
        key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
        shutdownRemoteOutputIfDrained()
    }

    private fun shutdownRemoteOutputIfDrained() {
        if (!finFromApp || pendingToRemote.isNotEmpty()) return
        try {
            if (channel.isConnected) channel.shutdownOutput()
        } catch (ignored: IOException) {
            // The peer may already be gone; the read side will notice.
        }
        if (finToApp) closeInternal(sendReset = false)
    }

    private fun readFromRemote() {
        val key = selectionKey ?: return
        // The socket can become readable before the app has acknowledged our SYN/ACK, so
        // anything held back from the proxy's reply has to go first or the stream would
        // arrive out of order.
        flushEarlyFromRemote()
        while (true) {
            val allowance = windowRemaining()
            if (allowance <= 0) {
                // The app has not acknowledged what we already sent; stop reading so the
                // backlog builds in the kernel socket buffer rather than in our heap.
                key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv())
                remoteReadsPaused = true
                return
            }

            val buffer = ByteBuffer.allocate(minOf(segmentSize, allowance))
            val read = channel.read(buffer)
            when {
                read > 0 -> {
                    buffer.flip()
                    val payload = ByteArray(read)
                    buffer.get(payload)
                    emit(
                        flags = TcpFlags.PSH or TcpFlags.ACK,
                        sequenceNumber = sendNext,
                        payload = payload,
                    )
                    sendNext = PacketFactory.nextSequence(sendNext, read)
                    bytesReceived += read
                    onBytes(bytesSent, bytesReceived)
                    lastActivityMillis = System.currentTimeMillis()
                }
                read == 0 -> return
                else -> { // end of stream from the remote server
                    if (!finToApp) {
                        emit(flags = TcpFlags.FIN or TcpFlags.ACK, sequenceNumber = sendNext)
                        sendNext = PacketFactory.nextSequence(sendNext, 1)
                        finToApp = true
                    }
                    key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv())
                    if (finFromApp) closeInternal(sendReset = false)
                    return
                }
            }
        }
    }

    private fun resumeRemoteReadsIfPossible() {
        if (!remoteReadsPaused || windowRemaining() <= 0) return
        val key = selectionKey ?: return
        remoteReadsPaused = false
        try {
            key.interestOps(key.interestOps() or SelectionKey.OP_READ)
            selectorLoop.wakeup()
        } catch (ignored: CancelledKeyException) {
            closeInternal(sendReset = false)
        }
    }

    /** How many more bytes the app's advertised window will accept. */
    private fun windowRemaining(): Int {
        val inFlight = ((sendNext - sendUnacked) and 0xFFFFFFFFL).toInt()
        return (peerWindow - inFlight).coerceAtLeast(0)
    }

    private fun emit(
        flags: Int,
        sequenceNumber: Long,
        payload: ByteArray? = null,
        mss: Int? = null,
    ) {
        sink.write(
            PacketFactory.buildTcp(
                source = remoteAddress,
                sourcePort = remotePort,
                destination = appAddress,
                destinationPort = appPort,
                sequenceNumber = sequenceNumber,
                acknowledgementNumber = recvNext,
                flags = flags,
                // Advertise a window shrunk by whatever we have not yet pushed to the socket,
                // so a slow server throttles the app instead of growing our queue.
                window = (DEFAULT_WINDOW - pendingBytes).coerceIn(0, DEFAULT_WINDOW),
                payload = payload,
                mssOption = mss,
            ),
        )
    }

    /** Tears the flow down and tells the app with a reset. */
    @Synchronized
    fun abort() = closeInternal(sendReset = true)

    @Synchronized
    fun close() = closeInternal(sendReset = false)

    private fun closeInternal(sendReset: Boolean) {
        if (state == State.CLOSED) return
        state = State.CLOSED

        if (sendReset) {
            emit(flags = TcpFlags.RST or TcpFlags.ACK, sequenceNumber = sendNext)
        }
        pendingToRemote.clear()
        pendingBytes = 0
        proxyOut = null
        earlyFromRemote = null
        selectionKey?.let { selectorLoop.cancel(it) }
        try {
            channel.close()
        } catch (ignored: IOException) {
        }
        onClosed(this)
    }

    private companion object {
        const val TAG = "TcpFlow"
        const val DEFAULT_WINDOW = 65535
        const val MIN_SEGMENT = 536

        /** A SOCKS reply is at most 262 bytes; this leaves room for it and then some. */
        const val PROXY_BUFFER = 512

        const val DIRECT_HANDSHAKE_MILLIS = 30_000L

        /** Tor may still be bootstrapping, so a routed connection is given far longer. */
        const val PROXY_HANDSHAKE_MILLIS = Tor.HANDSHAKE_TIMEOUT_MILLIS

        /**
         * Compares sequence numbers in the 32-bit space, where "less than" is defined by the
         * signed difference so the comparison stays correct across a wrap.
         */
        fun sequenceLessOrEqual(a: Long, b: Long): Boolean =
            ((b - a) and 0xFFFFFFFFL).toInt() >= 0
    }
}
