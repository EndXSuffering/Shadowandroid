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

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            refresh()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            refresh()
        }

        override fun onLost(network: Network) {
            refresh()
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
        refresh()
    }

    fun stop() {
        try {
            connectivityManager.unregisterNetworkCallback(callback)
        } catch (ignored: IllegalArgumentException) {
        }
    }

    private fun refresh() {
        var type = NetworkType.OTHER
        var servers: List<InetAddress> = emptyList()

        for (network in connectivityManager.allNetworks) {
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) continue

            type = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.MOBILE
                else -> NetworkType.OTHER
            }
            connectivityManager.getLinkProperties(network)?.dnsServers?.let {
                if (it.isNotEmpty()) servers = it
            }
            // A validated Wi-Fi link wins; keep looking only while we have not found one.
            if (type == NetworkType.WIFI) break
        }

        currentType = type
        dnsServers = servers.ifEmpty { FALLBACK_DNS }
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
