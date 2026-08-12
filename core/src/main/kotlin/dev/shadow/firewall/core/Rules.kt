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
 * Decides allow or block. Called once per DNS query and once per new connection, never per
 * packet, so it can afford the string work in [matches].
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

    /**
     * Verdict for a DNS query, where the name is exactly what the app asked for.
     *
     * This is the only place a hostname is trusted enough to block on. A blocked name is
     * answered with NXDOMAIN and never resolves, so the connection is never attempted.
     */
    fun decideHostname(hostname: String): Decision {
        val snapshot = rules
        // The user's allowlist is the escape hatch for a list's false positive, so it is
        // checked before anything that could block.
        if (matches(hostname, snapshot.allowedDomains)) return Decision.ALLOW

        if (matches(hostname, snapshot.blockedDomains)) {
            return Decision.block(BlockReason.DOMAIN_BLOCKLIST)
        }
        if (snapshot.useBlocklists) {
            blocklists.match(hostname)?.let { list ->
                return Decision.block(BlockReason.SUBSCRIBED_LIST, list.title)
            }
        }
        return Decision.ALLOW
    }

    /**
     * Verdict for a connection.
     *
     * [hostname] here is a *reverse* lookup — the last name we saw resolve to this address —
     * and on shared hosting it is regularly the wrong one. claude.ai and a blocked tracker
     * can sit on the same Cloudflare address; a storefront and its ad subdomain share a
     * CloudFront one. So a reverse-derived name may only ever permit a connection, never
     * condemn it. Domain blocking belongs in [decideHostname], against the query itself.
     */
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

        // Permissive use of the reverse name is safe: the worst case is letting something
        // through that the DNS-time check would already have caught.
        val allowlisted = hostname != null && matches(hostname, snapshot.allowedDomains)

        // Address rules are literal IPs taken from the lists, so they carry no ambiguity.
        if (snapshot.useBlocklists && destinationAddress != null && !allowlisted) {
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
