package dev.shadow.firewall.vpn

import android.util.Log
import dev.shadow.firewall.core.FlowKey
import dev.shadow.firewall.core.PacketFactory
import dev.shadow.firewall.core.TcpFlags
import dev.shadow.firewall.core.TcpSegment
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
) : SelectableFlow {

    enum class State { CONNECTING, HANDSHAKE, ESTABLISHED, CLOSED }

    private val channel: SocketChannel = SocketChannel.open()
    private var selectionKey: SelectionKey? = null

    private var state = State.CONNECTING

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
            channel.connect(InetSocketAddress(remoteAddress, remotePort))
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
            if (state == State.HANDSHAKE) state = State.ESTABLISHED
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
        key.interestOps(SelectionKey.OP_READ)
        sendSynAck()
        state = State.HANDSHAKE
        // A retransmitted SYN carrying data can queue bytes before the socket was ready.
        if (pendingToRemote.isNotEmpty()) drainToRemote(key)
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

        /**
         * Compares sequence numbers in the 32-bit space, where "less than" is defined by the
         * signed difference so the comparison stays correct across a wrap.
         */
        fun sequenceLessOrEqual(a: Long, b: Long): Boolean =
            ((b - a) and 0xFFFFFFFFL).toInt() >= 0
    }
}
