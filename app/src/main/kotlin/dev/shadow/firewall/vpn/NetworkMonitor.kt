package dev.shadow.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import dev.shadow.firewall.core.NetworkType
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks which kind of network is underneath the tunnel, so "block on mobile data" can mean
 * something, and collects the DNS servers the tunnel should advertise.
 *
 * The VPN's own network is skipped: asking the connectivity manager for "the active network"
 * while we are the active VPN would just describe our own tunnel.
 */
class NetworkMonitor(context: Context) {

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    var currentType: NetworkType = NetworkType.OTHER
        private set

    @Volatile
    var dnsServers: List<InetAddress> = emptyList()
        private set

    /**
     * Set when the user pinned a specific Private DNS hostname ("strict" mode). Android then
     * has no cleartext fallback, so refusing port 853 would leave the device with no DNS at
     * all — the encrypted-DNS block has to stand down.
     */
    @Volatile
    var strictPrivateDnsHostname: String? = null
        private set

    /** What we currently know about one network the callback has told us about. */
    private class Link(
        var capabilities: NetworkCapabilities? = null,
        var linkProperties: LinkProperties? = null,
    )

    // Built up from the callback rather than polled. ConnectivityManager.allNetworks was the
    // obvious way to enumerate these, but it is deprecated, and the callback is both the
    // supported route and the more accurate one: it only reports networks matching our request.
    private val links = ConcurrentHashMap<Network, Link>()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            links.getOrPut(network) { Link() }
            recompute()
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            links.getOrPut(network) { Link() }.capabilities = capabilities
            recompute()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            links.getOrPut(network) { Link() }.linkProperties = linkProperties
            recompute()
        }

        override fun onLost(network: Network) {
            links.remove(network)
            recompute()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            // Only physical transports; our own tunnel does not have these.
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .build()
        try {
            connectivityManager.registerNetworkCallback(request, callback)
        } catch (error: SecurityException) {
            Log.w(TAG, "cannot register network callback", error)
        }
    }

    fun stop() {
        try {
            connectivityManager.unregisterNetworkCallback(callback)
        } catch (ignored: IllegalArgumentException) {
        }
        links.clear()
    }

    private fun recompute() {
        var type = NetworkType.OTHER
        var servers: List<InetAddress> = emptyList()
        var strictPrivateDns: String? = null

        for ((_, link) in links) {
            val capabilities = link.capabilities ?: continue
            // Defensive: our request excludes VPN transports, so this should never match.
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) continue

            val candidate = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.MOBILE
                else -> NetworkType.OTHER
            }
            // Take this link unless we already settled on Wi-Fi, which wins over the rest.
            if (type == NetworkType.WIFI && candidate != NetworkType.WIFI) continue

            type = candidate
            link.linkProperties?.let { properties ->
                properties.dnsServers.let { if (it.isNotEmpty()) servers = it }
                // Non-null only in strict mode; opportunistic DoT leaves it unset.
                properties.privateDnsServerName?.let { strictPrivateDns = it }
            }
            if (type == NetworkType.WIFI) break
        }

        currentType = type
        dnsServers = servers.ifEmpty { FALLBACK_DNS }
        strictPrivateDnsHostname = strictPrivateDns
    }

    /** DNS servers to hand the tunnel, preferring IPv4 when IPv6 is switched off. */
    fun tunnelDnsServers(includeIpv6: Boolean): List<InetAddress> {
        val servers = dnsServers.ifEmpty { FALLBACK_DNS }
        val filtered = if (includeIpv6) servers else servers.filterIsInstance<Inet4Address>()
        return filtered.ifEmpty { FALLBACK_DNS.filterIsInstance<Inet4Address>() }
    }

    private companion object {
        const val TAG = "NetworkMonitor"

        /** Used only when the platform will not tell us what the link's resolvers are. */
        val FALLBACK_DNS: List<InetAddress> = listOf(
            InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)),
            InetAddress.getByAddress(byteArrayOf(9, 9, 9, 9)),
        )
    }
}
