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
            channel.connect(InetSocketAddress(remoteAddress, remotePort))
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
        val buffer = ByteBuffer.allocate(maxDatagram)
        try {
            while (true) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read <= 0) return
                buffer.flip()
                val payload = ByteArray(read)
                buffer.get(payload)

                lastActivityMillis = System.currentTimeMillis()
                bytesReceived += read
                onBytes(bytesSent, bytesReceived)
                onResponse(this, payload)

                sink.write(
                    PacketFactory.buildUdp(
                        source = remoteAddress,
                        sourcePort = remotePort,
                        destination = appAddress,
                        destinationPort = appPort,
                        payload = payload,
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
    }
}
