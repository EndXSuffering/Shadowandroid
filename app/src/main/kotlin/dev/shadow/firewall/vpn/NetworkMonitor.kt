package dev.shadow.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import dev.shadow.firewall.core.NetworkType
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
            connectivityManager.registerDefaultNetworkCallback(defaultCallback)
        } catch (error: SecurityException) {
            Log.w(TAG, "cannot register network callback", error)
        }
        seedFromActiveNetwork()
    }

    // ------------------------------------------------------------ default network

    /**
     * The resolvers advertised by the network this app's own sockets go out on — which, since
     * the app excludes itself from its tunnel, is the physical network underneath, not the VPN.
     * Lookups the firewall forwards travel on that network, so these are the servers reachable
     * from it: a home router's address is only valid while that router is the way out.
     */
    @Volatile
    var defaultDnsServers: List<InetAddress> = emptyList()
        private set

    /** Whether that network is Wi-Fi, for "use the network's DNS on Wi-Fi only". */
    @Volatile
    var defaultIsWifi: Boolean = false
        private set

    @Volatile
    private var defaultNetwork: Network? = null

    /**
     * Follows Android's choice of default network directly, rather than inferring it from the
     * links above: it is exactly the network a forwarded lookup will leave on, including a
     * Wi-Fi network Android has not validated yet, such as one behind a sign-in page.
     */
    private val defaultCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            adoptDefault(network)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (network == defaultNetwork) {
                defaultIsWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            }
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (network == defaultNetwork) defaultDnsServers = linkProperties.dnsServers
        }

        override fun onLost(network: Network) {
            // A switch arrives as onAvailable for the new network; this only clears the state
            // when the old default is lost with nothing taking its place.
            if (network == defaultNetwork) {
                defaultNetwork = null
                defaultDnsServers = emptyList()
                defaultIsWifi = false
            }
        }
    }

    /** Reads a new default network's details at once, so no lookup sees the old network's. */
    private fun adoptDefault(network: Network) {
        defaultNetwork = network
        connectivityManager.getNetworkCapabilities(network)?.let {
            defaultIsWifi = it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        }
        connectivityManager.getLinkProperties(network)?.let { defaultDnsServers = it.dnsServers }
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
            if (defaultNetwork == null) adoptDefault(network)
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
        try {
            connectivityManager.unregisterNetworkCallback(defaultCallback)
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

    private companion object {
        const val TAG = "NetworkMonitor"
    }
}
