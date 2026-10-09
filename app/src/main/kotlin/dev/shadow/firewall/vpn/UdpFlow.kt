package dev.shadow.firewall.vpn

import android.util.Log
import dev.shadow.firewall.core.FlowKey
import dev.shadow.firewall.core.PacketFactory
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey

/**
 * One UDP conversation, relayed over a connected [DatagramChannel].
 *
 * UDP has no handshake to emulate, so this is mostly plumbing: datagrams from the app go out
 * on a protected socket, replies come back wrapped in a spoofed IP header. DNS gets one extra
 * step, since sniffing the replies is how the traffic log learns hostnames.
 */
class UdpFlow(
    val key: FlowKey,
    val eventId: Long,
    private val appAddress: InetAddress,
    private val appPort: Int,
    private val remoteAddress: InetAddress,
    private val remotePort: Int,
    private val maxDatagram: Int,
    private val sink: PacketSink,
    private val selectorLoop: SelectorLoop,
    private val onResponse: (UdpFlow, ByteArray) -> Unit,
    private val onBytes: (sent: Long, received: Long) -> Unit,
    private val onClosed: (UdpFlow) -> Unit,
    /**
     * Where the socket really connects, when that differs from [remoteAddress]. Set for lookups
     * sent to the tunnel's stand-in resolver: they go to a real server, but the reply must look
     * as though the stand-in sent it, or the asking resolver would discard it.
     */
    private val upstream: InetSocketAddress? = null,
) : SelectableFlow {

    val isDns: Boolean get() = remotePort == DNS_PORT

    private val channel: DatagramChannel = DatagramChannel.open()
    private var selectionKey: SelectionKey? = null

    @Volatile private var closed = false
    private var bytesSent = 0L
    private var bytesReceived = 0L

    @Volatile
    var lastActivityMillis: Long = System.currentTimeMillis()
        private set

    val isClosed: Boolean get() = closed

    @Synchronized
    fun open(protect: (DatagramChannel) -> Boolean): Boolean {
        return try {
            channel.configureBlocking(false)
            if (!protect(channel)) {
                Log.w(TAG, "could not protect datagram socket for $key")
                close()
                return false
            }
            // Connecting fixes the peer so reads only accept replies from that server.
            channel.connect(upstream ?: InetSocketAddress(remoteAddress, remotePort))
            selectorLoop.register(channel, SelectionKey.OP_READ, this)
            true
        } catch (error: IOException) {
            Log.d(TAG, "udp open failed for $key: ${error.message}")
            close()
            false
        }
    }

    @Synchronized
    override fun onRegistered(registered: SelectionKey) {
        if (closed) {
            registered.cancel()
            return
        }
        selectionKey = registered
    }

    /** Forwards one datagram the app sent into the tunnel. */
    @Synchronized
    fun send(payload: ByteArray, offset: Int, length: Int) {
        if (closed) return
        lastActivityMillis = System.currentTimeMillis()
        try {
            channel.write(ByteBuffer.wrap(payload, offset, length))
            bytesSent += length
            onBytes(bytesSent, bytesReceived)
        } catch (error: IOException) {
            Log.d(TAG, "udp send failed for $key: ${error.message}")
            close()
        }
    }

    @Synchronized
    override fun onSelected(key: SelectionKey) {
        if (closed) return
        // One buffer per thread, not per wakeup. This used to allocate a fresh 64 KB buffer
        // every time a socket became readable — hundreds of times a second during a video
        // call or a QUIC download — only to throw it away.
        val buffer = receiveBuffer.get()!!
        try {
            while (true) {
                buffer.clear()
                buffer.limit(minOf(maxDatagram, buffer.capacity()))
                val read = channel.read(buffer)
                if (read <= 0) return

                lastActivityMillis = System.currentTimeMillis()
                bytesReceived += read
                onBytes(bytesSent, bytesReceived)
                // Only DNS replies are inspected, and only they need a copy of their own; the
                // packet built below copies the bytes out of the shared buffer itself.
                if (isDns) onResponse(this, buffer.array().copyOf(read))

                sink.write(
                    PacketFactory.buildUdp(
                        source = remoteAddress,
                        sourcePort = remotePort,
                        destination = appAddress,
                        destinationPort = appPort,
                        payload = buffer.array(),
                        payloadLength = read,
                    ),
                )
            }
        } catch (error: IOException) {
            Log.d(TAG, "udp read failed for $key: ${error.message}")
            close()
        }
    }

    @Synchronized
    fun close() {
        if (closed) return
        closed = true
        selectionKey?.let { selectorLoop.cancel(it) }
        try {
            channel.close()
        } catch (ignored: IOException) {
        }
        onClosed(this)
    }

    companion object {
        const val DNS_PORT = 53
        private const val TAG = "UdpFlow"

        /** Big enough for the largest UDP payload; reads only happen on the selector thread. */
        private val receiveBuffer: ThreadLocal<ByteBuffer> =
            ThreadLocal.withInitial { ByteBuffer.allocate(65_535) }
    }
}
