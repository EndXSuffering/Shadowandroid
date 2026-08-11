package dev.shadow.firewall.vpn

import android.net.ConnectivityManager
import android.os.Process
import android.util.Log
import dev.shadow.firewall.core.FlowKey
import dev.shadow.firewall.core.IpProto
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Works out which app owns a flow.
 *
 * The kernel knows, and since API 29 [ConnectivityManager.getConnectionOwnerUid] will tell a
 * VPN app for the connections it is carrying. This is the whole reason the app requires
 * Android 10: on older releases the only route was parsing `/proc/net/tcp`, which is no
 * longer readable by third-party apps.
 */
class UidResolver(private val connectivityManager: ConnectivityManager) {

    /** Returned when the socket is gone or the lookup is not permitted. */
    val unknownUid: Int = Process.INVALID_UID

    private val cache = object : LinkedHashMap<FlowKey, Int>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, Int>): Boolean =
            size > MAX_ENTRIES
    }

    /**
     * Resolves the owning uid for a flow. Call this as the connection is being set up, while
     * the socket is still in the kernel's table.
     */
    @Synchronized
    fun resolve(
        key: FlowKey,
        source: InetAddress,
        sourcePort: Int,
        destination: InetAddress,
        destinationPort: Int,
    ): Int {
        cache[key]?.let { return it }

        val uid = lookup(key.protocol, source, sourcePort, destination, destinationPort)
        // Only cache a definite answer; an unknown result may just be a lost race with the
        // kernel, and the next packet on this flow may well resolve.
        if (uid != unknownUid) cache[key] = uid
        return uid
    }

    private fun lookup(
        protocol: Int,
        source: InetAddress,
        sourcePort: Int,
        destination: InetAddress,
        destinationPort: Int,
    ): Int {
        if (protocol != IpProto.TCP && protocol != IpProto.UDP) return unknownUid
        return try {
            connectivityManager.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(source, sourcePort),
                InetSocketAddress(destination, destinationPort),
            )
        } catch (error: SecurityException) {
            // Thrown when we are not the active VPN, which happens briefly during teardown.
            Log.d(TAG, "uid lookup denied: ${error.message}")
            unknownUid
        } catch (error: IllegalArgumentException) {
            unknownUid
        }
    }

    @Synchronized
    fun forget(key: FlowKey) {
        cache.remove(key)
    }

    @Synchronized
    fun clear() = cache.clear()

    private companion object {
        const val TAG = "UidResolver"
        const val MAX_ENTRIES = 2048
    }
}
