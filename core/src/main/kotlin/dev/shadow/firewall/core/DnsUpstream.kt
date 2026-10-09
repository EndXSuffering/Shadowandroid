package dev.shadow.firewall.core

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** Where the firewall sends the lookups it lets through. */
enum class DnsMode {
    /** The Wi-Fi network's own resolver while on Wi-Fi; Cloudflare and Quad9 otherwise. */
    NETWORK_ON_WIFI,

    /** Whatever resolver the current network provides — the router on Wi-Fi, the carrier on mobile. */
    NETWORK_ALWAYS,

    /** Cloudflare and Quad9 on every network. */
    PUBLIC,
}

/**
 * Picks the real DNS server behind the tunnel's stand-in resolver.
 *
 * Apps are told to use [VIRTUAL_RESOLVERS] — addresses that exist only inside the tunnel. Every
 * lookup therefore arrives here, where the domain rules apply, and is then forwarded to a server
 * chosen *at that moment*. That is what makes following the network possible: the servers a
 * tunnel advertises are fixed when it is built, so advertising a home router's address directly
 * would leave DNS dead the moment the phone moved onto mobile data.
 */
object DnsUpstream {

    const val PORT = 53

    /**
     * Two, so the system resolver keeps its usual behaviour of trying a second server when the
     * first does not answer. Both sit in the tunnel's own address range.
     */
    val VIRTUAL_RESOLVERS: List<InetAddress> = listOf(
        InetAddress.getByAddress(byteArrayOf(10, 111, 222.toByte(), 53)),
        InetAddress.getByAddress(byteArrayOf(10, 111, 222.toByte(), 54)),
    )

    val PUBLIC_RESOLVERS: List<InetAddress> = listOf(
        InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)),
        InetAddress.getByAddress(byteArrayOf(9, 9, 9, 9)),
    )

    fun isVirtualResolver(address: InetAddress): Boolean = address in VIRTUAL_RESOLVERS

    /**
     * The servers to forward to, best first. Never empty: whenever the network has nothing
     * usable to offer, the answer is the public pair rather than no DNS at all.
     *
     * @param onWifi whether the network the firewall's own sockets currently use is Wi-Fi.
     * @param networkServers the resolvers that network advertises, in its own order.
     */
    fun choose(mode: DnsMode, onWifi: Boolean, networkServers: List<InetAddress>): List<InetAddress> {
        val wantsNetwork = when (mode) {
            DnsMode.NETWORK_ON_WIFI -> onWifi
            DnsMode.NETWORK_ALWAYS -> true
            DnsMode.PUBLIC -> false
        }
        if (!wantsNetwork) return PUBLIC_RESOLVERS
        return usable(networkServers).ifEmpty { PUBLIC_RESOLVERS }
    }

    /**
     * The real server behind one of the two stand-in addresses: the first for the first, the
     * second for the second, wrapping round when the network only offers one.
     */
    fun upstreamFor(virtual: InetAddress, servers: List<InetAddress>): InetAddress {
        require(servers.isNotEmpty()) { "choose() never returns an empty list" }
        val slot = VIRTUAL_RESOLVERS.indexOf(virtual).coerceAtLeast(0)
        return servers[slot % servers.size]
    }

    /**
     * Drops what cannot be forwarded to, and puts IPv4 first.
     *
     * A link-local IPv6 resolver (fe80::) is only reachable with an interface scope that a
     * forwarded socket may not carry, so it is used only when nothing else is offered. Anything
     * in the tunnel's own range would be a loop, and loopback is someone else's local resolver.
     */
    private fun usable(servers: List<InetAddress>): List<InetAddress> {
        val candidates = servers.filter { server ->
            !server.isLoopbackAddress && !server.isAnyLocalAddress && !isTunnelAddress(server)
        }
        val v4 = candidates.filterIsInstance<Inet4Address>()
        val v6 = candidates.filterIsInstance<Inet6Address>()
        val v6Routable = v6.filter { !it.isLinkLocalAddress }
        val v6LinkLocalScoped = v6.filter { it.isLinkLocalAddress && it.scopeId != 0 }
        return (v4 + v6Routable).ifEmpty { v6LinkLocalScoped }
    }

    private fun isTunnelAddress(address: InetAddress): Boolean {
        val bytes = address.address
        return bytes.size == 4 && bytes[0] == 10.toByte() && bytes[1] == 111.toByte() && bytes[2] == 222.toByte()
    }
}
