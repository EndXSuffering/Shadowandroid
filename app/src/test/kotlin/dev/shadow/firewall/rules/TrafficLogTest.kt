package dev.shadow.firewall.rules

import dev.shadow.firewall.core.BlockReason
import dev.shadow.firewall.core.ConnectionEvent
import dev.shadow.firewall.core.NetworkType
import dev.shadow.firewall.core.Verdict
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class TrafficLogTest {

    private var now = 1_000L
    private fun log(capacity: Int = 1000) = TrafficLog(capacity) { now }

    private fun event(id: Long) = ConnectionEvent(
        id = id, startedAtMillis = 0, updatedAtMillis = 0, uid = 10_000, packageName = "a",
        appLabel = "A", protocol = 6, destinationAddress = "1.2.3.4", destinationPort = 443,
        hostname = null, network = NetworkType.WIFI, verdict = Verdict.ALLOW, reason = BlockReason.NONE,
    )

    @Test
    fun `byte counts appear on the next publish`() {
        val subject = log()
        subject.record(event(1))
        now = 5_000
        subject.recordBytes(1, sent = 100, received = 2_000)
        subject.recordBytes(1, sent = 150, received = 9_000)
        subject.publish()

        val shown = subject.events.value.single()
        assertEquals(150, shown.bytesOut)
        assertEquals(9_000, shown.bytesIn)
        assertEquals(5_000, shown.updatedAtMillis)
    }

    @Test
    fun `nothing changed means nothing is republished`() {
        val subject = log()
        subject.record(event(1))
        subject.publish()
        val first = subject.events.value
        subject.recordBytes(1, 0, 0) // same as the event's own counts
        subject.publish()
        assertSame(first, subject.events.value)
    }

    @Test
    fun `newest first, and counts stay with their own entry`() {
        val subject = log()
        subject.record(event(1))
        subject.record(event(2))
        subject.recordBytes(1, 10, 20)
        subject.recordBytes(2, 30, 40)
        subject.publish()
        val (newest, oldest) = subject.events.value
        assertEquals(2, newest.id); assertEquals(30, newest.bytesOut)
        assertEquals(1, oldest.id); assertEquals(20, oldest.bytesIn)
    }

    @Test
    fun `evicted entries take their counters with them`() {
        val subject = log(capacity = 2)
        subject.record(event(1)); subject.record(event(2)); subject.record(event(3))
        subject.recordBytes(1, 999, 999) // evicted: must be ignored, not resurrected
        subject.publish()
        assertEquals(listOf(3L, 2L), subject.events.value.map { it.id })
        assertTrue(subject.events.value.none { it.bytesOut == 999L })
    }

    @Test
    fun `an unlogged flow's counts are ignored`() {
        // Allowed DNS flows are no longer logged and report bytes under event id 0.
        val subject = log()
        subject.record(event(1))
        subject.publish()
        val before = subject.events.value
        subject.recordBytes(0, 500, 500)
        subject.publish()
        assertSame(before, subject.events.value)
    }

    @Test
    fun `clear empties the log and its counters`() {
        val subject = log()
        subject.record(event(1))
        subject.clear()
        subject.recordBytes(1, 5, 5)
        subject.publish()
        assertTrue(subject.events.value.isEmpty())
    }
}
