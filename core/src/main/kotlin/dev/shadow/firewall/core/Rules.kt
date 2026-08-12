package dev.shadow.firewall.core

/** What the user has decided about one app. */
data class AppRule(
    val uid: Int,
    val blockWifi: Boolean = false,
    val blockMobile: Boolean = false,
) {
    fun blocks(network: NetworkType): Boolean = when (network) {
        NetworkType.WIFI -> blockWifi
        NetworkType.MOBILE -> blockMobile
        NetworkType.OTHER -> blockWifi && blockMobile
    }

    val isDefault: Boolean get() = !blockWifi && !blockMobile
}

/**
 * The complete firewall configuration. Immutable so the tunnel threads can read a snapshot
 * without locking while the UI builds the next one.
 */
data class RuleSet(
    /** When true, anything without an explicit allow is denied. */
    val blockByDefault: Boolean = false,
    val appRules: Map<Int, AppRule> = emptyMap(),
    /** Apps explicitly allowed through when [blockByDefault] is on. */
    val allowedUids: Set<Int> = emptySet(),
    /** Suffix-matched: "ads.example.com" also blocks "a.ads.example.com". */
    val blockedDomains: Set<String> = emptySet(),
    /** Wins over [blockedDomains], for punching holes in a broad blocklist entry. */
    val allowedDomains: Set<String> = emptySet(),
    /** Drop IPv6 so apps fall back to IPv4, where per-app rules are easier to reason about. */
    val blockIpv6: Boolean = false,
    /** Master switch for the subscribed ad and malware lists. */
    val useBlocklists: Boolean = true,
) {
    fun withAppRule(rule: AppRule): RuleSet {
        val next = appRules.toMutableMap()
        if (rule.isDefault) next.remove(rule.uid) else next[rule.uid] = rule
        return copy(appRules = next)
    }

    fun ruleFor(uid: Int): AppRule = appRules[uid] ?: AppRule(uid)
}

data class Decision(
    val verdict: Verdict,
    val reason: BlockReason,
    /** Which subscribed list matched, when [reason] is [BlockReason.SUBSCRIBED_LIST]. */
    val source: String? = null,
) {
    val isBlocked: Boolean get() = verdict == Verdict.BLOCK

    companion object {
        val ALLOW = Decision(Verdict.ALLOW, BlockReason.NONE)
        fun block(reason: BlockReason, source: String? = null) =
            Decision(Verdict.BLOCK, reason, source)
    }
}

/**
 * Decides allow or block for a flow. Called once per new connection, not per packet, so it
 * can afford the string work in [matches].
 */
class RuleEngine(rules: RuleSet = RuleSet()) {

    @Volatile
    var rules: RuleSet = rules

    /**
     * The subscribed ad and malware lists. Held separately from [rules] because the two are
     * updated on completely different schedules: rules when the user taps a switch, lists
     * when the background refresh finishes.
     */
    @Volatile
    var blocklists: BlocklistIndex = BlocklistIndex.EMPTY

    fun decide(
        uid: Int,
        network: NetworkType,
        hostname: String?,
        isIpv6: Boolean,
        /** The connection's destination IP, matched against the lists' address rules. */
        destinationAddress: String? = null,
    ): Decision {
        val snapshot = rules

        if (isIpv6 && snapshot.blockIpv6) {
            return Decision.block(BlockReason.IPV6_DISABLED)
        }

        // The user's own allowlist overrides every domain rule, including the subscribed
        // lists. It is the only escape hatch when a list has a false positive, so nothing
        // downstream is allowed to override it.
        if (hostname != null && !matches(hostname, snapshot.allowedDomains)) {
            if (matches(hostname, snapshot.blockedDomains)) {
                return Decision.block(BlockReason.DOMAIN_BLOCKLIST)
            }
            if (snapshot.useBlocklists) {
                blocklists.match(hostname)?.let { list ->
                    return Decision.block(BlockReason.SUBSCRIBED_LIST, list.title)
                }
            }
        }

        // Address rules apply even when there was no lookup to inspect, which is what makes
        // them the one part of a list that DNS-over-HTTPS cannot route around. The user's
        // domain allowlist still wins, via the hostname branch above.
        if (snapshot.useBlocklists && destinationAddress != null &&
            (hostname == null || !matches(hostname, snapshot.allowedDomains))
        ) {
            blocklists.matchAddress(destinationAddress)?.let { list ->
                return Decision.block(BlockReason.SUBSCRIBED_LIST, list.title)
            }
        }

        val rule = snapshot.appRules[uid]
        if (rule != null && rule.blocks(network)) {
            return Decision.block(BlockReason.APP_RULE)
        }
        if (rule != null) {
            // An explicit rule that permits this network overrides a block-by-default policy.
            return Decision.ALLOW
        }

        if (snapshot.blockByDefault && uid !in snapshot.allowedUids) {
            return Decision.block(BlockReason.DEFAULT_POLICY)
        }
        return Decision.ALLOW
    }

    companion object {
        /**
         * True when [hostname] equals an entry in [domains] or is a subdomain of one.
         * Comparison is case-insensitive and ignores a trailing root dot.
         */
        fun matches(hostname: String, domains: Set<String>): Boolean {
            if (domains.isEmpty()) return false
            val name = normalise(hostname)
            if (name.isEmpty()) return false
            if (name in domains) return true

            var index = name.indexOf('.')
            while (index in 0 until name.length - 1) {
                if (name.substring(index + 1) in domains) return true
                index = name.indexOf('.', index + 1)
            }
            return false
        }

        /** Entries are stored normalised so [matches] can use plain set lookups. */
        fun normalise(domain: String): String =
            domain.trim().trimEnd('.').lowercase()

        fun normaliseAll(domains: Iterable<String>): Set<String> =
            domains.map(::normalise).filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
    }
}
