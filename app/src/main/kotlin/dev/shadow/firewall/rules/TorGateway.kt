package dev.shadow.firewall.rules

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import dev.shadow.firewall.core.Tor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/** Whether a routed connection would actually have somewhere to go right now. */
enum class TorAvailability {
    /** Orbot is not on the device, so nothing can be routed. */
    NOT_INSTALLED,

    /** Orbot is installed but its proxy is not answering; it is stopped or still starting. */
    NOT_RUNNING,

    /** The proxy accepted a connection. */
    READY,

    /** Not checked yet. */
    UNKNOWN,
}

/**
 * The app's only contact with Tor.
 *
 * There is no Tor client in here. Routing is done by handing connections to Orbot, which is
 * the Tor Project's own Android app, and this class exists to answer three questions about it:
 * is it installed, is it listening, and how does the user start it.
 */
class TorGateway(private val context: Context) {

    val isOrbotInstalled: Boolean
        get() = runCatching {
            context.packageManager.getPackageInfo(Tor.ORBOT_PACKAGE, 0)
        }.isSuccess

    /**
     * Opens and immediately drops a connection to the SOCKS port. There is no cheaper way to
     * know Orbot is actually serving: it can be installed, and even in the foreground, while
     * its proxy is still bootstrapping.
     */
    suspend fun check(): TorAvailability = withContext(Dispatchers.IO) {
        if (!isOrbotInstalled) return@withContext TorAvailability.NOT_INSTALLED
        val reachable = runCatching {
            Socket().use { socket ->
                socket.connect(
                    InetSocketAddress(Tor.SOCKS_HOST, Tor.SOCKS_PORT),
                    PROBE_TIMEOUT_MILLIS,
                )
            }
            true
        }.getOrDefault(false)
        if (reachable) TorAvailability.READY else TorAvailability.NOT_RUNNING
    }

    /**
     * Asks Orbot to start. Orbot has honoured this broadcast for years but may ignore it —
     * newer versions want the user to confirm in their own UI — so [open] is the fallback.
     */
    fun requestStart() {
        val intent = Intent(ACTION_START_TOR)
            .setPackage(Tor.ORBOT_PACKAGE)
            .putExtra(EXTRA_PACKAGE_NAME, context.packageName)
        runCatching { context.sendBroadcast(intent) }
            .onFailure { Log.w(TAG, "could not ask Orbot to start: ${it.message}") }
    }

    /** Brings Orbot to the foreground, or sends the user to install it. */
    fun open() {
        val launch = context.packageManager.getLaunchIntentForPackage(Tor.ORBOT_PACKAGE)
        val intent = launch ?: Intent(Intent.ACTION_VIEW, Uri.parse(ORBOT_STORE_URL))
        runCatching {
            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.onFailure { Log.w(TAG, "could not open Orbot: ${it.message}") }
    }

    private companion object {
        const val TAG = "TorGateway"
        const val PROBE_TIMEOUT_MILLIS = 1_500
        const val ACTION_START_TOR = "org.torproject.android.intent.action.START"
        const val EXTRA_PACKAGE_NAME = "org.torproject.android.intent.extra.PACKAGE_NAME"
        const val ORBOT_STORE_URL =
            "https://play.google.com/store/apps/details?id=${Tor.ORBOT_PACKAGE}"
    }
}
