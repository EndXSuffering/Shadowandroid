package dev.shadow.firewall.rules

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Process
import android.provider.Telephony
import dev.shadow.firewall.core.UidNames
import dev.shadow.firewall.vpn.AppIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * One row in the app list. Android can share a uid between packages, and the firewall works
 * at uid granularity, so an entry may cover several packages.
 */
data class InstalledApp(
    val uid: Int,
    val packageNames: List<String>,
    val label: String,
    val isSystem: Boolean,
) {
    val primaryPackage: String get() = packageNames.first()
    val sharesUid: Boolean get() = packageNames.size > 1
}

/**
 * Lists the apps that can reach the network, and maps a uid back to a name for the traffic
 * log. Lookups are cached because the log resolves a uid on every new flow.
 */
class AppRepository(context: Context) {

    private val packageManager: PackageManager = context.packageManager

    /**
     * The default SMS app, which is also the one that sends picture messages. MMS often rides
     * a separate carrier APN that a userspace tunnel cannot reach, so this is the app most
     * likely to need excluding.
     */
    val defaultSmsPackage: String? =
        runCatching { Telephony.Sms.getDefaultSmsPackage(context) }.getOrNull()
    private val identityCache = HashMap<Int, AppIdentity>()
    private val iconCache = HashMap<String, Drawable?>()

    /** Apps that declare INTERNET, which are the only ones a firewall rule can affect. */
    suspend fun loadApps(): List<InstalledApp> = withContext(Dispatchers.IO) {
        val packages = packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val byUid = HashMap<Int, MutableList<android.content.pm.PackageInfo>>()

        for (info in packages) {
            val requested = info.requestedPermissions ?: continue
            if (!requested.contains(android.Manifest.permission.INTERNET)) continue
            val applicationInfo = info.applicationInfo ?: continue
            byUid.getOrPut(applicationInfo.uid) { mutableListOf() }.add(info)
        }

        byUid.map { (uid, infos) ->
            // When several packages share a uid, label the entry with the first one
            // alphabetically so the list order is stable between launches.
            val sorted = infos.sortedBy { it.packageName }
            val applicationInfo = sorted.first().applicationInfo!!
            InstalledApp(
                uid = uid,
                packageNames = sorted.map { it.packageName },
                label = packageManager.getApplicationLabel(applicationInfo).toString(),
                isSystem = (applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            )
        }.sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
    }

    /**
     * Resolves a uid to a package and label; safe to call from the tunnel threads.
     *
     * Four sources are tried in order, because the package manager alone leaves a lot of
     * ordinary traffic nameless: Android's own daemons own no package, sandboxed renderers
     * own no package, and an app uninstalled since the connection was logged no longer has
     * one either. Anything still unnamed is at least classified rather than called unknown.
     */
    @Synchronized
    fun identify(uid: Int): AppIdentity {
        identityCache[uid]?.let { return it }

        val identity = resolveIdentity(uid)
        identityCache[uid] = identity
        return identity
    }

    private fun resolveIdentity(uid: Int): AppIdentity {
        if (uid == Process.INVALID_UID || uid < 0) {
            return AppIdentity(null, UidNames.describe(uid))
        }

        // 1. The normal case: one or more installed packages share this uid.
        packageManager.getPackagesForUid(uid)?.takeIf { it.isNotEmpty() }?.let { names ->
            val name = names.sorted().first()
            val label = runCatching {
                packageManager.getApplicationLabel(packageManager.getApplicationInfo(name, 0))
                    .toString()
            }.getOrNull()
            return AppIdentity(name, label ?: name)
        }

        // 2. A shared user ID, which getPackagesForUid does not always answer for.
        runCatching { packageManager.getNameForUid(uid) }.getOrNull()?.let { shared ->
            return AppIdentity(shared, UidNames.systemService(uid) ?: shared)
        }

        // 3. One of Android's service uids, which never has a package.
        UidNames.systemService(uid)?.let { return AppIdentity(null, it) }

        // 4. Nothing can name it, so say what kind of uid it is.
        return AppIdentity(null, UidNames.describe(uid))
    }

    /**
     * The uids behind a set of package names, for rules that are stored by package but have to
     * be enforced by uid. Packages that are no longer installed simply drop out.
     */
    fun uidsFor(packageNames: Set<String>): Set<Int> = packageNames.mapNotNullTo(HashSet()) { name ->
        runCatching { packageManager.getApplicationInfo(name, 0).uid }.getOrNull()
    }

    @Synchronized
    fun icon(packageName: String): Drawable? = iconCache.getOrPut(packageName) {
        runCatching { packageManager.getApplicationIcon(packageName) }.getOrNull()
    }

    @Synchronized
    fun invalidate() {
        identityCache.clear()
        iconCache.clear()
    }
}
