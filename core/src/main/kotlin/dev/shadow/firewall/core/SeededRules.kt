package dev.shadow.firewall.core

/**
 * Domain rules the app adds to the user's own lists, once each.
 *
 * Some fixes are known to be right for almost everyone but belong to no subscribed list: the
 * hosts that serve Yahoo Mail's inbox ads are on no list at all, and PayPal's bot check is
 * blocked by a tracker list whose other entries are worth keeping. Rather than hide those
 * choices inside the app, they are written into the user's Blocked and Allowed domains, where
 * they can be seen and deleted like anything the user typed.
 *
 * Seeding is versioned so that it respects the user afterwards. Each release is applied
 * exactly once: delete a seeded domain and it stays deleted, and a later release only ever
 * adds its own new entries. A seed also never contradicts the user — an allow is skipped if
 * the user already blocks that exact domain, and vice versa, since the allowed list wins over
 * everything and would otherwise silently override a deliberate choice.
 */
object SeededRules {

    class Release(
        val blocked: List<String> = emptyList(),
        val allowed: List<String> = emptyList(),
    )

    /** Append only. Changing or removing a shipped release would not reach anyone. */
    val RELEASES: List<Release> = listOf(
        Release(
            blocked = listOf(
                // Yahoo Mail's inbox ads. The ad slot, and the auction behind it; none of
                // these carry mail, which comes from mail.yahoo.com.
                "gam.mail.yahoosandbox.net",
                "pbs.yahoo.com",
                "pbd.yahoo.com",
            ),
            allowed = listOf(
                // PayPal's bot check (a CNAME to Radware Bot Manager) and Radware's challenge
                // host. Tracker lists block both because the sensor fingerprints the device,
                // but without it PayPal cannot tell a person from a script, so login and
                // payment fail. AdGuard's own list exempts the challenge host for this reason.
                "bm.paypal.com",
                "validate.perfdrive.com",
            ),
        ),
    )

    val LATEST: Int get() = RELEASES.size

    data class Result(
        val blocked: Set<String>,
        val allowed: Set<String>,
        /** The release now applied, to be stored so none is applied twice. */
        val version: Int,
    ) {
        fun changed(fromBlocked: Set<String>, fromAllowed: Set<String>): Boolean =
            blocked != fromBlocked || allowed != fromAllowed
    }

    /**
     * Applies every release after [appliedVersion] to the user's current lists. Both sets are
     * expected already normalised, as the rule store keeps them.
     */
    fun apply(
        blocked: Set<String>,
        allowed: Set<String>,
        appliedVersion: Int,
        releases: List<Release> = RELEASES,
    ): Result {
        if (appliedVersion >= releases.size) return Result(blocked, allowed, appliedVersion)

        val nextBlocked = blocked.toMutableSet()
        val nextAllowed = allowed.toMutableSet()
        for (release in releases.drop(appliedVersion.coerceAtLeast(0))) {
            for (domain in RuleEngine.normaliseAll(release.blocked)) {
                if (domain !in nextAllowed) nextBlocked += domain
            }
            for (domain in RuleEngine.normaliseAll(release.allowed)) {
                if (domain !in nextBlocked) nextAllowed += domain
            }
        }
        return Result(nextBlocked, nextAllowed, releases.size)
    }
}
