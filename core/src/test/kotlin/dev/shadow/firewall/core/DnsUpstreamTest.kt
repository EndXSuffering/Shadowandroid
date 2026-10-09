package dev.shadow.firewall.core

import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsUpstreamTest {

    private fun ip(text: String): InetAddress = InetAddress.getByName(text)

    private val router = ip("192.168.1.1")
    private val carrier = ip("10.177.0.34")
    private val publicPair = DnsUpstream.PUBLIC_RESOLVERS

    @Test
    fun `on wifi, the wifi network's own resolver is used`() {
        val chosen = DnsUpstream.choose(DnsMode.NETWORK_ON_WIFI, onWifi = true, listOf(router))
        assertEquals(listOf(router), chosen)
    }

    @Test
    fun `off wifi, network-on-wifi falls back to the public pair`() {
        // What was asked for: the router's DNS at home, Cloudflare and Quad9 elsewhere.
        val chosen = DnsUpstream.choose(DnsMode.NETWORK_ON_WIFI, onWifi = false, listOf(carrier))
        assertEquals(publicPair, chosen)
    }

    @Test
    fun `network-always uses the carrier's resolver on mobile data`() {
        val chosen = DnsUpstream.choose(DnsMode.NETWORK_ALWAYS, onWifi = false, listOf(carrier))
        assertEquals(listOf(carrier), chosen)
    }

    @Test
    fun `public ignores the network entirely`() {
        assertEquals(publicPair, DnsUpstream.choose(DnsMode.PUBLIC, onWifi = true, listOf(router)))
    }

    @Test
    fun `a network that offers nothing gets the public pair, never no DNS`() {
        assertEquals(publicPair, DnsUpstream.choose(DnsMode.NETWORK_ON_WIFI, onWifi = true, emptyList()))
        assertEquals(publicPair, DnsUpstream.choose(DnsMode.NETWORK_ALWAYS, onWifi = false, emptyList()))
    }

    @Test
    fun `ipv4 resolvers are preferred over ipv6 ones`() {
        val v6 = ip("2001:4860:4860::8888")
        val chosen = DnsUpstream.choose(DnsMode.NETWORK_ALWAYS, onWifi = true, listOf(v6, router))
        assertEquals(listOf(router, v6), chosen)
    }

    @Test
    fun `an unscoped link-local ipv6 resolver is not used`() {
        // fe80:: needs an interface to be reachable; without one there is nowhere to send it.
        val linkLocal = ip("fe80::1")
        val chosen = DnsUpstream.choose(DnsMode.NETWORK_ON_WIFI, onWifi = true, listOf(linkLocal))
        assertEquals(publicPair, chosen)
    }

    @Test
    fun `a scoped link-local ipv6 resolver is used when it is all there is`() {
        val scoped = Inet6Address.getByAddress(null, ip("fe80::1").address, 3)
        val chosen = DnsUpstream.choose(DnsMode.NETWORK_ON_WIFI, onWifi = true, listOf(scoped))
        assertEquals(listOf<InetAddress>(scoped), chosen)
    }

    @Test
    fun `the tunnel's own addresses and loopback are never forwarded to`() {
        // Either would send lookups straight back into the firewall, or to someone else's
        // local resolver.
        val loops = listOf(ip("10.111.222.53"), ip("127.0.0.53"))
        assertEquals(publicPair, DnsUpstream.choose(DnsMode.NETWORK_ALWAYS, onWifi = true, loops))
    }

    @Test
    fun `each stand-in address maps to its own server`() {
        val (first, second) = DnsUpstream.VIRTUAL_RESOLVERS
        val two = listOf(router, ip("192.168.1.2"))
        assertEquals(router, DnsUpstream.upstreamFor(first, two))
        assertEquals(ip("192.168.1.2"), DnsUpstream.upstreamFor(second, two))
    }

    @Test
    fun `with one server, both stand-ins reach it`() {
        val (first, second) = DnsUpstream.VIRTUAL_RESOLVERS
        assertEquals(router, DnsUpstream.upstreamFor(first, listOf(router)))
        assertEquals(router, DnsUpstream.upstreamFor(second, listOf(router)))
    }

    @Test
    fun `the stand-ins are recognised, and real servers are not`() {
        assertTrue(DnsUpstream.isVirtualResolver(ip("10.111.222.53")))
        assertTrue(DnsUpstream.isVirtualResolver(ip("10.111.222.54")))
        assertFalse(DnsUpstream.isVirtualResolver(ip("1.1.1.1")))
        assertFalse(DnsUpstream.isVirtualResolver(router))
    }
}
