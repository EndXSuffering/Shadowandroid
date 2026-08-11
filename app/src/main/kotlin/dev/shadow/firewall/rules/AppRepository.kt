package dev.shadow.firewall.rules

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Process
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

    /** Resolves a uid to a package and label; safe to call from the tunnel threads. */
    @Synchronized
    fun identify(uid: Int): AppIdentity {
        identityCache[uid]?.let { return it }

        val identity = when {
            uid == Process.INVALID_UID || uid < 0 -> AppIdentity(null, null)
            uid == Process.ROOT_UID -> AppIdentity("root", "Root")
            uid == Process.SYSTEM_UID -> AppIdentity("android", "Android System")
            else -> {
                val names = packageManager.getPackagesForUid(uid)
                if (names.isNullOrEmpty()) {
                    AppIdentity(null, null)
                } else {
                    val name = names.sorted().first()
                    val label = runCatching {
                        packageManager.getApplicationLabel(
                            packageManager.getApplicationInfo(name, 0),
                        ).toString()
                    }.getOrNull()
                    AppIdentity(name, label ?: name)
                }
            }
        }
        identityCache[uid] = identity
        return identity
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
