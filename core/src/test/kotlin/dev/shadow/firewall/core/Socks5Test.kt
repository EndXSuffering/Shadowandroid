package dev.shadow.firewall.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class Socks5Test {

    private val ipv4 = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34)

    private fun clientFor(port: Int = 443) =
        Socks5Client(Socks5.connectRequest(ipv4, port))

    /** A successful reply carrying a bound IPv4 address, which is what Tor sends back. */
    private fun successReply() =
        byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)

    @Test
    fun `connect request encodes an ipv4 destination`() {
        val request = Socks5.connectRequest(ipv4, 443)
        assertContentEquals(
            byteArrayOf(5, 1, 0, 1, 93.toByte(), 184.toByte(), 216.toByte(), 34, 1, 187.toByte()),
            request,
        )
    }

    @Test
    fun `connect request encodes an ipv6 destination`() {
        val address = ByteArray(16) { if (it == 15) 1 else 0 }
        val request = Socks5.connectRequest(address, 80)
        assertEquals(22, request.size)
        assertEquals(Socks5.ADDRESS_IPV6, request[3].toInt())
        assertEquals(80, ((request[20].toInt() and 0xFF) shl 8) or (request[21].toInt() and 0xFF))
    }

    @Test
    fun `a clean handshake sends the request then reports ready`() {
        val client = clientFor()
        assertContentEquals(byteArrayOf(5, 1, 0), client.greeting())

        val selection = byteArrayOf(5, 0)
        val afterGreeting = client.onBytes(selection, 0, selection.size)
        val send = assertIs<Socks5Client.Step.Send>(afterGreeting)
        assertEquals(Socks5.COMMAND_CONNECT, send.bytes[1].toInt())

        val reply = successReply()
        val ready = assertIs<Socks5Client.Step.Ready>(client.onBytes(reply, 0, reply.size))
        assertTrue(ready.earlyData.isEmpty())
    }

    @Test
    fun `a reply split across reads is reassembled`() {
        val client = clientFor()
        client.onBytes(byteArrayOf(5), 0, 1).let { assertIs<Socks5Client.Step.NeedMore>(it) }
        assertIs<Socks5Client.Step.Send>(client.onBytes(byteArrayOf(0), 0, 1))

        val reply = successReply()
        assertIs<Socks5Client.Step.NeedMore>(client.onBytes(reply, 0, 4))
        assertIs<Socks5Client.Step.Ready>(client.onBytes(reply, 4, reply.size - 4))
    }

    @Test
    fun `server bytes arriving with the reply are not lost`() {
        // Losing these would corrupt the first bytes of the relayed stream, which is the kind
        // of failure that looks like a broken server rather than a broken proxy client.
        val client = clientFor()
        client.onBytes(byteArrayOf(5, 0), 0, 2)

        val combined = successReply() + byteArrayOf(72, 84, 84, 80)
        val ready = assertIs<Socks5Client.Step.Ready>(client.onBytes(combined, 0, combined.size))
        assertContentEquals(byteArrayOf(72, 84, 84, 80), ready.earlyData)
    }

    @Test
    fun `a domain name in the reply is measured by its length byte`() {
        val client = clientFor()
        client.onBytes(byteArrayOf(5, 0), 0, 2)

        val reply = byteArrayOf(5, 0, 0, Socks5.ADDRESS_DOMAIN.toByte(), 3, 97, 98, 99, 0, 80)
        assertIs<Socks5Client.Step.Ready>(client.onBytes(reply, 0, reply.size))
    }

    @Test
    fun `a refusal is reported with the reason the proxy gave`() {
        val client = clientFor()
        client.onBytes(byteArrayOf(5, 0), 0, 2)

        val refused = byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)
        val failure = assertIs<Socks5Client.Step.Failed>(client.onBytes(refused, 0, refused.size))
        assertEquals("connection refused", failure.reason)
    }

    @Test
    fun `a proxy demanding authentication fails rather than retrying`() {
        val client = clientFor()
        val demand = byteArrayOf(5, 0xFF.toByte())
        val failure = assertIs<Socks5Client.Step.Failed>(client.onBytes(demand, 0, demand.size))
        assertTrue(failure.reason.contains("authentication"))
    }

    @Test
    fun `something that is not socks fails immediately`() {
        val client = clientFor()
        val http = byteArrayOf(72, 84)
        assertIs<Socks5Client.Step.Failed>(client.onBytes(http, 0, http.size))
    }
}
