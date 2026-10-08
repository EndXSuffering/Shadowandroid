package dev.shadow.firewall.vpn

import android.util.Log
import java.io.FileOutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Anything that can hand a finished IP packet back to the app that is being filtered. */
interface PacketSink {
    fun write(packet: ByteArray)
}

/**
 * Serialises writes to the tun file descriptor onto one thread.
 *
 * Packets are produced by the tunnel reader thread and by the socket selector thread, and a
 * [FileOutputStream] on a tun fd is not safe to share between them.
 *
 * Nothing handed to [write] is ever dropped while the tunnel is up. That is not a nicety:
 * [TcpFlow] never retransmits toward the app, because it is built on the guarantee that what
 * it hands the tun device arrives. A dropped data segment would leave the app re-acknowledging
 * the same byte forever with nothing to resend it — a connection that hangs until the idle
 * sweeper kills it. So a full queue makes the producer wait instead, which also throttles it:
 * the selector stops reading sockets until the app can take more.
 */
class TunWriter(
    private val output: FileOutputStream,
    queueCapacity: Int = 1024,
) : PacketSink {

    private val queue = ArrayBlockingQueue<ByteArray>(queueCapacity)
    private val running = AtomicBoolean(true)

    private val thread = Thread({ loop() }, "tun-writer").apply {
        isDaemon = true
        start()
    }

    override fun write(packet: ByteArray) {
        // Wait in short slices rather than indefinitely, so a producer blocked on a full queue
        // still notices the tunnel being torn down.
        while (running.get()) {
            try {
                if (queue.offer(packet, OFFER_SLICE_MILLIS, TimeUnit.MILLISECONDS)) return
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
    }

    private fun loop() {
        while (running.get()) {
            val packet = try {
                queue.poll(250, TimeUnit.MILLISECONDS) ?: continue
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
            try {
                output.write(packet)
            } catch (error: Exception) {
                // The fd is gone, which only happens on teardown. Stop accepting packets too,
                // or producers would wait forever on a queue that nothing drains any more.
                if (running.getAndSet(false)) Log.w(TAG, "tun write failed", error)
                return
            }
        }
    }

    fun stop() {
        if (running.compareAndSet(true, false)) {
            thread.interrupt()
        }
    }

    private companion object {
        const val TAG = "TunWriter"
        const val OFFER_SLICE_MILLIS = 50L
    }
}
