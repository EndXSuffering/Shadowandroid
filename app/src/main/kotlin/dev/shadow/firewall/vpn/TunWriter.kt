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
 */
class TunWriter(
    private val output: FileOutputStream,
    queueCapacity: Int = 1024,
) : PacketSink {

    private val queue = ArrayBlockingQueue<ByteArray>(queueCapacity)
    private val running = AtomicBoolean(true)
    @Volatile private var dropped = 0L

    private val thread = Thread({ loop() }, "tun-writer").apply {
        isDaemon = true
        start()
    }

    override fun write(packet: ByteArray) {
        if (!running.get()) return
        // Dropping is the right failure mode here: the queue only backs up when the tun
        // device is congested, and TCP will retransmit what the peer never acknowledges.
        if (!queue.offer(packet)) {
            dropped++
            if (dropped % 100 == 1L) {
                Log.w(TAG, "tun write queue full, dropped $dropped packets")
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
                if (running.get()) Log.w(TAG, "tun write failed", error)
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
    }
}
