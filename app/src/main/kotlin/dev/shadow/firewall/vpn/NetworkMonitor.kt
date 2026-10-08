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
 * something, and whether the user pinned a Private DNS server.
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
        @Volatile var capabilities: NetworkCapabilities? = null,
        @Volatile var linkProperties: LinkProperties? = null,
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
        seedFromActiveNetwork()
    }

    /**
     * Reads the current network synchronously, before the tunnel carries its first packet.
     *
     * The callback above answers asynchronously, and the tunnel used to be established and
     * judging connections before it had said anything — so every connection in that window
     * was judged as being on an "other" network. An app blocked only on Wi-Fi got through
     * for the first moments after every start, and the tunnel restarts whenever a bypass,
     * Tor or IPv6 setting changes. The default network for this app is the physical one even
     * while the VPN is up, because the app excludes itself from its own tunnel.
     */
    private fun seedFromActiveNetwork() {
        try {
            val network = connectivityManager.activeNetwork ?: return
            val link = links.getOrPut(network) { Link() }
            if (link.capabilities == null) {
                link.capabilities = connectivityManager.getNetworkCapabilities(network)
            }
            if (link.linkProperties == null) {
                link.linkProperties = connectivityManager.getLinkProperties(network)
            }
            recompute()
        } catch (error: SecurityException) {
            Log.w(TAG, "cannot read the active network", error)
        }
    }

    fun stop() {
        try {
            connectivityManager.unregisterNetworkCallback(callback)
        } catch (ignored: IllegalArgumentException) {
        }
        links.clear()
    }

    @Synchronized
    private fun recompute() {
        var type = NetworkType.OTHER
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
            // Non-null only in strict mode; opportunistic DoT leaves it unset.
            link.linkProperties?.privateDnsServerName?.let { strictPrivateDns = it }
            if (type == NetworkType.WIFI) break
        }

        currentType = type
        strictPrivateDnsHostname = strictPrivateDns
    }

    /**
     * The resolvers the tunnel advertises to apps.
     *
     * Deliberately public ones, not the network's own. The tunnel's DNS servers are fixed
     * when it is established, but the network underneath is not: a router address taken from
     * home Wi-Fi stops answering the moment the phone moves to mobile data, and DNS would be
     * dead until the next rebuild. A public resolver answers on any network. The cost is that
     * lookups go to Cloudflare and Quad9 rather than to your provider, and that a captive
     * portal which only answers its own DNS may not load until you sign in with the firewall
     * off. This was always the behaviour in practice — the monitor had no answer yet when the
     * tunnel was built, so it fell back to these — and is now stated rather than accidental.
     */
    fun tunnelDnsServers(includeIpv6: Boolean): List<InetAddress> =
        if (includeIpv6) PUBLIC_RESOLVERS else PUBLIC_RESOLVERS.filterIsInstance<Inet4Address>()

    private companion object {
        const val TAG = "NetworkMonitor"

        val PUBLIC_RESOLVERS: List<InetAddress> = listOf(
            InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)),
            InetAddress.getByAddress(byteArrayOf(9, 9, 9, 9)),
        )
    }
}
