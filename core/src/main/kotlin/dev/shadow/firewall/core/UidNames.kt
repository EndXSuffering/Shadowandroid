package dev.shadow.firewall.core

/**
 * Works out what a uid is when the package manager cannot name it.
 *
 * A traffic log full of "Unknown app" is useless, and the label hides at least five different
 * situations: a lookup that failed, one of Android's own service uids, an isolated process, an
 * app in a second profile, and an app that has since been uninstalled. They call for different
 * responses from the user, so they should not read the same.
 *
 * Pure data and arithmetic, kept in `core` so it can be unit tested.
 */
object UidNames {

    /** Returned by the kernel lookup when the socket could not be matched to an owner. */
    const val UNAVAILABLE = -1

    /** Android's uid layout, from `android_filesystem_config.h` and `UserHandle`. */
    const val PER_USER_RANGE = 100_000
    const val FIRST_APPLICATION_UID = 10_000
    const val LAST_APPLICATION_UID = 19_999
    const val FIRST_ISOLATED_UID = 90_000
    const val LAST_ISOLATED_UID = 99_999

    /**
     * Fixed uids Android reserves for its own daemons. None of them owns an installed package,
     * so the package manager returns nothing for them, yet several are constant fixtures in a
     * traffic log — the DNS resolver carries every lookup the device makes.
     *
     * Only the ones that actually open sockets are listed; anything absent still shows its
     * number rather than being guessed at.
     */
    private val SYSTEM_SERVICES: Map<Int, String> = mapOf(
        0 to "Android root",
        1000 to "Android system",
        1001 to "Telephony",
        1002 to "Bluetooth",
        1010 to "Wi-Fi",
        1013 to "Media server",
        1014 to "DHCP client",
        1016 to "VPN service",
        1019 to "DRM service",
        1020 to "Multicast DNS",
        1021 to "Location (GPS)",
        1027 to "NFC",
        1029 to "IPv6 translation (clat)",
        1041 to "Audio server",
        1047 to "Camera server",
        1051 to "Android DNS resolver",
        1053 to "WebView sandbox",
        1066 to "Usage statistics",
        1073 to "Network stack",
        2000 to "ADB shell",
        9999 to "Nobody",
    )

    /** Which Android user (main profile, work profile, second user) a uid belongs to. */
    fun userId(uid: Int): Int = if (uid < 0) 0 else uid / PER_USER_RANGE

    /** The uid with its profile offset removed, which is what identifies the app itself. */
    fun appId(uid: Int): Int = if (uid < 0) uid else uid % PER_USER_RANGE

    fun isApplication(uid: Int): Boolean = appId(uid) in FIRST_APPLICATION_UID..LAST_APPLICATION_UID

    /** Sandboxed child processes: browser renderers and the like. They own no package. */
    fun isIsolated(uid: Int): Boolean = appId(uid) in FIRST_ISOLATED_UID..LAST_ISOLATED_UID

    /** The name of an Android service uid, or null if this is not one. */
    fun systemService(uid: Int): String? = SYSTEM_SERVICES[appId(uid)]

    /**
     * A label for a uid the package manager could not name, saying what kind of thing it is
     * and, where it matters, why no package is available.
     */
    fun describe(uid: Int): String {
        if (uid == UNAVAILABLE || uid < 0) return "Unattributed connection"

        systemService(uid)?.let { return withProfile(uid, it) }

        val appId = appId(uid)
        val label = when {
            isIsolated(uid) -> "Sandboxed process (uid $appId)"
            appId < FIRST_APPLICATION_UID -> "Android service (uid $appId)"
            isApplication(uid) -> "Removed app (uid $appId)"
            else -> "Shared user ID $appId"
        }
        return withProfile(uid, label)
    }

    /**
     * Why a connection could not be attributed, for the detail view. Null when the uid is
     * known and the only thing missing is a package name.
     */
    fun unattributedExplanation(uid: Int): String? =
        if (uid == UNAVAILABLE || uid < 0) {
            "The socket closed before the system could say which app owned it. Short-lived " +
                "connections and traffic from the OS itself often land here."
        } else {
            null
        }

    private fun withProfile(uid: Int, label: String): String {
        val user = userId(uid)
        return if (user > 0) "$label · profile $user" else label
    }
}
