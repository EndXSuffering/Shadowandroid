package dev.shadow.firewall.vpn

import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.IOException
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TunWriterTest {

    /** A tun fd stand-in: records packets, optionally slowly, optionally never returning. */
    private class FakeTun(
        private val delayMillis: Long = 0,
        private val gate: CountDownLatch? = null,
        private val failAfter: Int = Int.MAX_VALUE,
    ) : FileOutputStream(FileDescriptor()) {
        val written: MutableList<ByteArray> = Collections.synchronizedList(ArrayList())
        override fun write(b: ByteArray) {
            if (written.size >= failAfter) throw IOException("fd closed")
            gate?.await()
            if (delayMillis > 0) Thread.sleep(delayMillis)
            written += b
        }
    }

    private fun packet(producer: Int, index: Int) = byteArrayOf(producer.toByte(), (index shr 8).toByte(), index.toByte())

    @Test
    fun `a full queue makes producers wait instead of dropping`() {
        // The old writer dropped here. TcpFlow never retransmits toward the app, so a dropped
        // data segment was a connection that hung for good.
        val tun = FakeTun(delayMillis = 1)
        val writer = TunWriter(tun, queueCapacity = 4)
        val perProducer = 150
        val producers = (0 until 2).map { p ->
            thread { repeat(perProducer) { i -> writer.write(packet(p, i)) } }
        }
        producers.forEach { it.join(30_000) }

        val deadline = System.currentTimeMillis() + 10_000
        while (tun.written.size < 2 * perProducer && System.currentTimeMillis() < deadline) Thread.sleep(10)
        writer.stop()

        assertEquals(2 * perProducer, tun.written.size, "every packet must reach the tun device")
        // And each producer's packets arrive in the order it wrote them.
        for (p in 0 until 2) {
            val order = synchronized(tun.written) {
                tun.written.filter { it[0].toInt() == p }
                    .map { ((it[1].toInt() and 0xFF) shl 8) or (it[2].toInt() and 0xFF) }
            }
            assertEquals((0 until perProducer).toList(), order)
        }
    }

    @Test
    fun `stopping releases a producer stuck on a full queue`() {
        val gate = CountDownLatch(1) // the writer thread blocks on this forever
        val writer = TunWriter(FakeTun(gate = gate), queueCapacity = 2)
        // One packet is taken by the (now stuck) writer thread, two fill the queue.
        repeat(3) { writer.write(packet(0, it)) }

        val returned = CountDownLatch(1)
        thread { writer.write(packet(0, 99)); returned.countDown() }
        assertTrue(!returned.await(300, TimeUnit.MILLISECONDS), "producer should be waiting")

        writer.stop()
        assertTrue(returned.await(2, TimeUnit.SECONDS), "stop must release a waiting producer")
        gate.countDown()
    }

    @Test
    fun `a dead tun fd stops the writer rather than hanging producers`() {
        // If the writer thread dies and producers keep waiting for queue space, the whole
        // relay freezes. After a write failure, producers must return promptly.
        val writer = TunWriter(FakeTun(failAfter = 0), queueCapacity = 2)
        writer.write(packet(0, 0)) // the writer takes this, fails, and stops
        Thread.sleep(300)

        val returned = CountDownLatch(1)
        thread {
            repeat(10) { writer.write(packet(0, it)) }
            returned.countDown()
        }
        assertTrue(returned.await(2, TimeUnit.SECONDS), "producers must not hang on a dead writer")
    }
}
