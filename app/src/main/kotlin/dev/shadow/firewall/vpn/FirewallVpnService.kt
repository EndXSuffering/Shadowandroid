package dev.shadow.firewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.shadow.firewall.FirewallApp
import dev.shadow.firewall.R
import dev.shadow.firewall.core.RuleEngine
import dev.shadow.firewall.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Inet4Address
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel

/**
 * The VPN that is not a VPN.
 *
 * Nothing leaves the device through a remote server. The tunnel exists purely so that every
 * packet an app sends passes through this process first, which is the only way a non-rooted
 * app can inspect or block another app's traffic on Android.
 */
class FirewallVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var tunnel: ParcelFileDescriptor? = null
    private var relay: TunnelRelay? = null
    private var networkMonitor: NetworkMonitor? = null
    private var publishJob: Job? = null

    /** Guards against a second start while the first is still loading rules from disk. */
    @Volatile private var starting = false

    /**
     * The parts of the configuration that are baked into the interface at establish() time.
     * Routes and the excluded-app set cannot be changed on a live tunnel, so a change here
     * means tearing it down and building a new one.
     */
    private data class TunnelShape(val blockIpv6: Boolean, val bypassedPackages: Set<String>)

    private var establishedShape = TunnelShape(false, emptySet())

    private val ruleEngine = RuleEngine()

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        // The tunnel is the product; if the process is killed the system should bring it back.
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN app took over, or the user revoked consent.
        Log.i(TAG, "VPN permission revoked")
        stopTunnel()
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        scope.cancel()
        super.onDestroy()
    }

    // -------------------------------------------------------------- lifecycle

    private fun startTunnel() {
        if (tunnel != null || starting) return
        starting = true

        // Must happen promptly after startForegroundService, before anything can block.
        startForeground(NOTIFICATION_ID, buildNotification(blocked = 0))

        scope.launch {
            val app = application as FirewallApp
            // Load the saved rules before building the tunnel: the IPv6 setting decides
            // which routes the interface gets, so it cannot be applied afterwards.
            val initial = app.ruleStore.settings.first()
            ruleEngine.rules = initial.rules
            ruleEngine.blocklists = app.blocklistRepository.index.value
            establishedShape = TunnelShape(initial.rules.blockIpv6, initial.rules.bypassedPackages)

            bringUp(app)
            starting = false

            // Blocklists refresh on their own schedule, so track them separately.
            launch {
                app.blocklistRepository.index.collect { ruleEngine.blocklists = it }
            }

            // Keep the engine's snapshot in step with what the user configures from here on.
            app.ruleStore.settings.collect { settings ->
                ruleEngine.rules = settings.rules
                val shape = TunnelShape(settings.rules.blockIpv6, settings.rules.bypassedPackages)
                if (shape != establishedShape && tunnel != null) {
                    establishedShape = shape
                    tearDown()
                    bringUp(app)
                }
            }
        }
    }

    private fun bringUp(app: FirewallApp) {
        val monitor = NetworkMonitor(this).also { it.start(); networkMonitor = it }

        val descriptor = establishTunnel(monitor)
        if (descriptor == null) {
            Log.e(TAG, "could not establish the tunnel")
            _state.value = VpnState.Stopped
            stopSelf()
            return
        }
        tunnel = descriptor

        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val relay = TunnelRelay(
            tunInput = FileInputStream(descriptor.fileDescriptor),
            tunOutput = FileOutputStream(descriptor.fileDescriptor),
            mtu = MTU,
            ruleEngine = ruleEngine,
            hostnames = app.hostnameCache,
            uidResolver = UidResolver(connectivityManager),
            networkMonitor = monitor,
            identify = app.appRepository::identify,
            onEvent = app.trafficLog::record,
            onBytes = app.trafficLog::recordBytes,
            protectTcp = { channel: SocketChannel -> protect(channel.socket()) },
            protectUdp = { channel: DatagramChannel -> protect(channel.socket()) },
        )
        relay.start()
        this.relay = relay

        // Coalesce the flood of per-packet counter updates into a steady redraw.
        publishJob = scope.launch {
            while (true) {
                app.trafficLog.publish()
                updateNotification(relay.flowsBlocked)
                delay(PUBLISH_INTERVAL_MILLIS)
            }
        }

        _state.value = VpnState.Running
        Log.i(TAG, "tunnel established")
    }

    private fun establishTunnel(monitor: NetworkMonitor): ParcelFileDescriptor? {
        val blockIpv6 = ruleEngine.rules.blockIpv6
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(MTU)
            // A link-local-ish address the tunnel owns; nothing else on the device uses it.
            .addAddress(TUNNEL_IPV4, 32)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)

        if (!blockIpv6) {
            builder.addAddress(TUNNEL_IPV6, 128)
            builder.addRoute("::", 0)
        }

        for (server in monitor.tunnelDnsServers(includeIpv6 = !blockIpv6)) {
            // Advertising the real resolvers keeps DNS working; the queries still come
            // through the tunnel, where the domain rules are applied.
            if (blockIpv6 && server !is Inet4Address) continue
            runCatching { builder.addDnsServer(server) }
        }

        // Our own sockets must not be filtered, or the relay would loop back into itself.
        runCatching { builder.addDisallowedApplication(packageName) }

        // Apps the user has excluded. Their traffic never enters the tunnel, so nothing here
        // filters or even sees it. An uninstalled package throws, which is not worth failing
        // the whole tunnel over.
        for (excluded in ruleEngine.rules.bypassedPackages) {
            runCatching { builder.addDisallowedApplication(excluded) }
                .onFailure { Log.w(TAG, "cannot exclude $excluded: ${it.message}") }
        }

        builder.setConfigureIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )

        return try {
            builder.establish()
        } catch (error: IllegalStateException) {
            Log.e(TAG, "establish failed", error)
            null
        } catch (error: SecurityException) {
            // Consent was not granted, or was withdrawn between the prompt and here.
            Log.e(TAG, "establish denied", error)
            null
        }
    }

    /** Drops the interface and its relay, but leaves the service running. */
    private fun tearDown() {
        publishJob?.cancel()
        publishJob = null
        relay?.stop()
        relay = null
        networkMonitor?.stop()
        networkMonitor = null
        runCatching { tunnel?.close() }
        tunnel = null
        _state.value = VpnState.Stopped
    }

    private fun stopTunnel() {
        starting = false
        tearDown()
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // -------------------------------------------------------------- notification

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    private fun buildNotification(blocked: Long): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, FirewallVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(resources.getQuantityString(R.plurals.notification_blocked, blocked.toInt(), blocked))
            .setContentIntent(open)
            .addAction(0, getString(R.string.action_stop), stop)
            .setOngoing(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private var lastNotifiedBlocked = -1L

    private fun updateNotification(blocked: Long) {
        if (blocked == lastNotifiedBlocked) return
        lastNotifiedBlocked = blocked
        getSystemService(NotificationManager::class.java)
            ?.notify(NOTIFICATION_ID, buildNotification(blocked))
    }

    companion object {
        private const val TAG = "FirewallVpnService"

        const val ACTION_START = "dev.shadow.firewall.START"
        const val ACTION_STOP = "dev.shadow.firewall.STOP"

        private const val CHANNEL_ID = "firewall_status"
        private const val NOTIFICATION_ID = 1
        private const val MTU = 1500
        private const val PUBLISH_INTERVAL_MILLIS = 750L
        private const val TUNNEL_IPV4 = "10.111.222.1"
        private const val TUNNEL_IPV6 = "fd00:1:2:3::1"

        private val _state = MutableStateFlow<VpnState>(VpnState.Stopped)

        /** Whether the tunnel is up, observed by the UI. */
        val state: StateFlow<VpnState> = _state.asStateFlow()

        fun start(context: Context) {
            val intent = Intent(context, FirewallVpnService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, FirewallVpnService::class.java).setAction(ACTION_STOP),
            )
        }
    }
}

sealed interface VpnState {
    data object Stopped : VpnState
    data object Running : VpnState

    val isRunning: Boolean get() = this is Running
}
