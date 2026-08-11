package dev.shadow.firewall.core

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsTest {

    private fun name(value: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (label in value.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(0)
        return out.toByteArray()
    }

    private fun u16(value: Int) = byteArrayOf(((value ushr 8) and 0xFF).toByte(), (value and 0xFF).toByte())

    private fun query(host: String, type: Int = Dns.TYPE_A, id: Int = 0x1234): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(u16(id))
        out.write(u16(0x0100)) // standard query, recursion desired
        out.write(u16(1)) // one question
        out.write(u16(0))
        out.write(u16(0))
        out.write(u16(0))
        out.write(name(host))
        out.write(u16(type))
        out.write(u16(1)) // IN
        return out.toByteArray()
    }

    private fun response(
        host: String,
        addresses: List<String>,
        ttl: Long = 300,
        compressed: Boolean = true,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(u16(0x1234))
        out.write(u16(0x8180)) // response, recursion available
        out.write(u16(1))
        out.write(u16(addresses.size))
        out.write(u16(0))
        out.write(u16(0))
        out.write(name(host))
        out.write(u16(Dns.TYPE_A))
        out.write(u16(1))
        for (address in addresses) {
            val bytes = InetAddress.getByName(address).address
            if (compressed) {
                // Pointer back to the question's name at offset 12.
                out.write(byteArrayOf(0xC0.toByte(), 0x0C))
            } else {
                out.write(name(host))
            }
            out.write(u16(if (bytes.size == 4) Dns.TYPE_A else Dns.TYPE_AAAA))
            out.write(u16(1))
            out.write(byteArrayOf(0, 0, ((ttl ushr 8) and 0xFF).toByte(), (ttl and 0xFF).toByte()))
            out.write(u16(bytes.size))
            out.write(bytes)
        }
        return out.toByteArray()
    }

    @Test
    fun `parses a query name`() {
        val message = assertNotNull(Dns.parse(query("ads.example.com")))
        assertTrue(!message.isResponse)
        assertEquals("ads.example.com", message.queryName)
        assertEquals(Dns.TYPE_A, message.questions.single().type)
    }

    @Test
    fun `parses a response with compressed names`() {
        val message = assertNotNull(Dns.parse(response("example.com", listOf("93.184.216.34", "93.184.216.35"))))
        assertTrue(message.isResponse)
        assertEquals("example.com", message.queryName)
        assertEquals(2, message.answers.size)
        assertEquals(
            listOf("93.184.216.34", "93.184.216.35"),
            message.addresses().map { it.hostAddress },
        )
        assertEquals(300L, message.answers.first().ttlSeconds)
    }

    @Test
    fun `parses a response with uncompressed names`() {
        val message = assertNotNull(
            Dns.parse(response("example.com", listOf("93.184.216.34"), compressed = false)),
        )
        assertEquals("example.com", message.answers.single().name)
    }

    @Test
    fun `parses an ipv6 answer`() {
        val message = assertNotNull(Dns.parse(response("example.com", listOf("2606:2800:220:1::1"))))
        assertEquals(Dns.TYPE_AAAA, message.answers.single().type)
        assertEquals("2606:2800:220:1:0:0:0:1", message.addresses().single().hostAddress)
    }

    @Test
    fun `parses a message that is offset inside a larger buffer`() {
        val payload = query("example.com")
        val framed = ByteArray(40 + payload.size) { 0x5A }
        System.arraycopy(payload, 0, framed, 40, payload.size)

        val message = assertNotNull(Dns.parse(framed, 40, payload.size))
        assertEquals("example.com", message.queryName)
    }

    @Test
    fun `builds an nxdomain reply that mirrors the question`() {
        val request = query("tracker.example.com", id = 0xBEEF)
        val reply = assertNotNull(Dns.buildNxDomain(request))

        val parsed = assertNotNull(Dns.parse(reply))
        assertTrue(parsed.isResponse)
        assertEquals(0xBEEF, parsed.id)
        assertEquals(Dns.RCODE_NAME_ERROR, parsed.responseCode)
        assertEquals("tracker.example.com", parsed.queryName)
        assertTrue(parsed.answers.isEmpty())
    }

    @Test
    fun `nxdomain reply preserves the recursion desired bit`() {
        val reply = assertNotNull(Dns.buildNxDomain(query("example.com")))
        val flags = ((reply[2].toInt() and 0xFF) shl 8) or (reply[3].toInt() and 0xFF)
        assertTrue(flags and 0x8000 != 0, "QR must be set")
        assertTrue(flags and 0x0100 != 0, "RD must be echoed")
        assertTrue(flags and 0x0080 != 0, "RA must be set")
    }

    @Test
    fun `rejects truncated messages instead of throwing`() {
        assertNull(Dns.parse(ByteArray(0)))
        assertNull(Dns.parse(ByteArray(11)))
        val truncated = query("example.com").copyOfRange(0, 16)
        assertNull(Dns.parse(truncated))
    }

    @Test
    fun `rejects a name compression loop`() {
        // A pointer at offset 12 that points at itself would spin forever without the hop cap.
        val bytes = ByteArray(20)
        System.arraycopy(u16(0x1234), 0, bytes, 0, 2)
        System.arraycopy(u16(0x0100), 0, bytes, 2, 2)
        System.arraycopy(u16(1), 0, bytes, 4, 2)
        bytes[12] = 0xC0.toByte()
        bytes[13] = 0x0C
        assertNull(Dns.parse(bytes))
    }

    @Test
    fun `rejects a header claiming more questions than the buffer can hold`() {
        val bytes = query("example.com")
        bytes[4] = 0xFF.toByte()
        bytes[5] = 0xFF.toByte()
        assertNull(Dns.parse(bytes))
    }

    @Test
    fun `rejects an rdlength that runs past the end`() {
        val bytes = response("example.com", listOf("1.2.3.4"))
        // Inflate the final RDLENGTH field so it overruns the buffer.
        bytes[bytes.size - 5] = 0xFF.toByte()
        val message = assertNotNull(Dns.parse(bytes))
        assertTrue(message.answers.isEmpty(), "overrunning record must be dropped, not read")
    }
}
