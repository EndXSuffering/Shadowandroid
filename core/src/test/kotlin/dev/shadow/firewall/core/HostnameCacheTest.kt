package dev.shadow.firewall.core

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HostnameCacheTest {

    private var now = 1_000_000L
    private fun cache(maxEntries: Int = 4096) =
        HostnameCache(maxEntries = maxEntries, clock = { now })

    @Test
    fun `remembers and returns a hostname`() {
        val subject = cache()
        subject.put("93.184.216.34", "Example.COM.", ttlSeconds = 300)
        assertEquals("example.com", subject.get("93.184.216.34"))
    }

    @Test
    fun `entries expire once their ttl passes`() {
        val subject = cache()
        subject.put("1.2.3.4", "short.example", ttlSeconds = 90)
        now += 89_000
        assertEquals("short.example", subject.get("1.2.3.4"))
        now += 2_000
        assertNull(subject.get("1.2.3.4"))
    }

    @Test
    fun `a very short ttl is floored so the log keeps the name a while`() {
        val subject = cache()
        subject.put("1.2.3.4", "flappy.example", ttlSeconds = 1)
        now += 30_000
        assertEquals("flappy.example", subject.get("1.2.3.4"))
    }

    @Test
    fun `a very long ttl is capped`() {
        val subject = cache()
        subject.put("1.2.3.4", "stable.example", ttlSeconds = 30 * 24 * 3600)
        now += 7 * 60 * 60 * 1000
        assertNull(subject.get("1.2.3.4"))
    }

    @Test
    fun `oldest entries are evicted past the size limit`() {
        val subject = cache(maxEntries = 3)
        subject.put("10.0.0.1", "one.example", 300)
        subject.put("10.0.0.2", "two.example", 300)
        subject.put("10.0.0.3", "three.example", 300)
        // Touch the first entry so it is no longer the least recently used.
        assertNotNull(subject.get("10.0.0.1"))
        subject.put("10.0.0.4", "four.example", 300)

        assertEquals(3, subject.size())
        assertEquals("one.example", subject.get("10.0.0.1"))
        assertNull(subject.get("10.0.0.2"))
        assertEquals("four.example", subject.get("10.0.0.4"))
    }

    @Test
    fun `recording a dns response indexes every answer under the queried name`() {
        val subject = cache()
        val message = assertNotNull(Dns.parse(responseWithCname()))
        subject.record(message)

        // Both addresses map to the name the app asked for, not the CNAME target.
        assertEquals("www.example.com", subject.get("93.184.216.34"))
        assertEquals("www.example.com", subject.get("93.184.216.35"))
    }

    @Test
    fun `recording a query is a no-op`() {
        val subject = cache()
        val queryBytes = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            write(7); write("example".toByteArray())
            write(3); write("com".toByteArray())
            write(0)
            write(byteArrayOf(0, 1, 0, 1))
        }.toByteArray()

        subject.record(assertNotNull(Dns.parse(queryBytes)))
        assertEquals(0, subject.size())
    }

    /** A response for www.example.com that CNAMEs to a CDN and then gives two A records. */
    private fun responseWithCname(): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) = out.write(byteArrayOf(((value ushr 8) and 0xFF).toByte(), (value and 0xFF).toByte()))
        fun name(value: String) {
            for (label in value.split('.')) { out.write(label.length); out.write(label.toByteArray()) }
            out.write(0)
        }

        u16(0x1234); u16(0x8180); u16(1); u16(3); u16(0); u16(0)
        name("www.example.com"); u16(Dns.TYPE_A); u16(1)

        out.write(byteArrayOf(0xC0.toByte(), 0x0C)); u16(Dns.TYPE_CNAME); u16(1)
        out.write(byteArrayOf(0, 0, 1, 44))
        val cname = ByteArrayOutputStream().apply {
            for (label in "cdn.example.net".split('.')) { write(label.length); write(label.toByteArray()) }
            write(0)
        }.toByteArray()
        u16(cname.size); out.write(cname)

        for (address in listOf("93.184.216.34", "93.184.216.35")) {
            out.write(byteArrayOf(0xC0.toByte(), 0x0C)); u16(Dns.TYPE_A); u16(1)
            out.write(byteArrayOf(0, 0, 1, 44))
            val bytes = InetAddress.getByName(address).address
            u16(bytes.size); out.write(bytes)
        }
        return out.toByteArray()
    }
}
