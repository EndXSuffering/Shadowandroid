package dev.shadow.firewall.core

/**
 * Reads the three formats published blocklists actually come in.
 *
 * - **hosts**: `0.0.0.0 ads.example.com`, the AdAway/StevenBlack style.
 * - **AdGuard/AdBlock**: `||ads.example.com^`, optionally `@@||...^` for an exception.
 * - **plain**: one bare domain per line.
 *
 * Detection is per line rather than per file, because real lists mix them and because a
 * mis-detected file would otherwise silently produce an empty list.
 *
 * Anything that cannot be enforced at the DNS level is skipped rather than approximated.
 * A rule like `||example.com/ads/banner.png` targets a path; treating it as a domain block
 * would take down the whole site, so it is dropped instead.
 */
object BlocklistParser {

    /** Whether a rule names a hostname or a literal IP address. */
    enum class Kind { DOMAIN, ADDRESS }

    /** A single parsed rule. [values] is usually one entry; hosts lines may carry several. */
    data class Rule(
        val values: List<String>,
        val isException: Boolean,
        val kind: Kind = Kind.DOMAIN,
    ) {
        val domains: List<String> get() = if (kind == Kind.DOMAIN) values else emptyList()
    }

    /** Hosts-file entries that describe the loopback interface, not something to block. */
    private val LOOPBACK_NAMES = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    )

    /** AdGuard modifiers that leave a rule as a plain domain block. */
    private val HARMLESS_MODIFIERS = setOf("important", "all")

    fun parseLine(rawLine: String): Rule? {
        val line = rawLine.trim()
        if (line.isEmpty()) return null
        // '!' is AdBlock's comment marker, '#' is the hosts one. A hosts entry always starts
        // with an IP address, so a leading '#' is never the start of a rule.
        if (line[0] == '!' || line[0] == '#') return null

        return when {
            line.startsWith("@@") -> parseAdBlock(line.substring(2), isException = true)
            line.startsWith("||") -> parseAdBlock(line, isException = false)
            line.startsWith("/") -> null // regular-expression rule
            looksLikeHostsEntry(line) -> parseHosts(line)
            else -> parseAdBlock(line, isException = false)
        }
    }

    /** Convenience for parsing a whole file; comments and unusable rules simply vanish. */
    fun parse(lines: Sequence<String>): ParsedList {
        val blocked = ArrayList<String>()
        val allowed = ArrayList<String>()
        val addresses = ArrayList<String>()
        var skipped = 0
        for (line in lines) {
            val rule = parseLine(line)
            if (rule == null) {
                if (line.isNotBlank() && !isComment(line)) skipped++
                continue
            }
            when {
                rule.kind == Kind.ADDRESS && !rule.isException -> addresses.addAll(rule.values)
                rule.kind == Kind.ADDRESS -> Unit // an exception for a literal address; rare
                rule.isException -> allowed.addAll(rule.values)
                else -> blocked.addAll(rule.values)
            }
        }
        return ParsedList(blocked, allowed, addresses, skipped)
    }

    data class ParsedList(
        val blocked: List<String>,
        val allowed: List<String>,
        /**
         * Literal IP addresses the list wants blocked. Malware lists carry these for hosts
         * that are reached without a lookup at all, which makes them the one part of a
         * blocklist that DNS-over-HTTPS cannot route around.
         */
        val blockedAddresses: List<String>,
        /** Non-comment lines we could not turn into a rule. */
        val skipped: Int,
    )

    private fun isComment(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("!") || trimmed.startsWith("#")
    }

    // ------------------------------------------------------------------ hosts

    private fun looksLikeHostsEntry(line: String): Boolean {
        val firstField = line.substringBefore(' ').substringBefore('\t')
        return firstField.isNotEmpty() && isIpAddress(firstField) && line.length > firstField.length
    }

    private fun parseHosts(line: String): Rule? {
        // Strip a trailing comment before splitting; "0.0.0.0 a.com # note" is common.
        val withoutComment = line.substringBefore('#').trim()
        val fields = withoutComment.split(' ', '\t').filter { it.isNotEmpty() }
        if (fields.size < 2) return null

        val domains = fields.drop(1)
            .map { RuleEngine.normalise(it) }
            .filter { it !in LOOPBACK_NAMES && isValidDomain(it) }
        return if (domains.isEmpty()) null else Rule(domains, isException = false)
    }

    // --------------------------------------------------------------- adblock

    private fun parseAdBlock(rawRule: String, isException: Boolean): Rule? {
        var rule = rawRule.trim()
        if (rule.isEmpty()) return null
        // Cosmetic and scriptlet rules have no DNS meaning.
        if (rule.contains("##") || rule.contains("#@#") || rule.contains("#%#") || rule.contains("#\$#")) {
            return null
        }
        if (rule.startsWith("/")) return null // regex

        var modifiers: String? = null
        val dollar = rule.indexOf('$')
        if (dollar >= 0) {
            modifiers = rule.substring(dollar + 1)
            rule = rule.substring(0, dollar)
        }
        // A rule with modifiers we do not model may mean something narrower than "block this
        // domain" — $denyallow and $client both do — so only pass the ones we understand.
        if (modifiers != null) {
            val names = modifiers.split(',').map { it.substringBefore('=').trim().lowercase() }
            if (names.any { it.isNotEmpty() && it !in HARMLESS_MODIFIERS }) return null
        }

        if (rule.startsWith("||")) rule = rule.substring(2)
        else if (rule.startsWith("|")) rule = rule.substring(1)
        if (rule.startsWith("http://")) rule = rule.removePrefix("http://")
        if (rule.startsWith("https://")) rule = rule.removePrefix("https://")

        // A path makes this a URL rule; blocking the whole host would over-block.
        val slash = rule.indexOf('/')
        if (slash >= 0) {
            val remainder = rule.substring(slash + 1)
            if (remainder.isNotEmpty()) return null
            rule = rule.substring(0, slash)
        }

        rule = rule.substringBefore('^').substringBefore('|')
        if (rule.contains('*')) return null // wildcards we cannot express as a suffix match
        rule = stripPort(rule)

        val token = RuleEngine.normalise(rule)
        if (token in LOOPBACK_NAMES) return null
        if (isIpAddress(token)) {
            val canonical = canonicalAddress(token) ?: return null
            return Rule(listOf(canonical), isException, Kind.ADDRESS)
        }
        if (!isValidDomain(token)) return null
        return Rule(listOf(token), isException)
    }

    /**
     * Removes a trailing `:port`, leaving IPv6 literals alone. A bare `2001:db8::1` is all
     * colons, so a naive split would truncate it to `2001`.
     */
    private fun stripPort(value: String): String {
        if (value.startsWith("[")) {
            // Bracketed IPv6, optionally with a port: [2001:db8::1]:443
            val close = value.indexOf(']')
            return if (close > 0) value.substring(1, close) else value
        }
        val colon = value.lastIndexOf(':')
        if (colon <= 0) return value
        // More than one colon means IPv6, which never carries a bare port suffix.
        if (value.indexOf(':') != colon) return value
        val port = value.substring(colon + 1)
        return if (port.isNotEmpty() && port.all { it in '0'..'9' }) value.substring(0, colon) else value
    }

    // ------------------------------------------------------------ validation

    /**
     * Accepts what can appear as a hostname in a blocklist. Deliberately strict: a bad entry
     * here becomes a domain the user cannot reach and cannot easily explain.
     */
    fun isValidDomain(candidate: String): Boolean {
        if (candidate.length !in 3..253) return false
        if (candidate.startsWith('.') || candidate.endsWith('.')) return false
        if (!candidate.contains('.')) return false // bare labels and TLDs are too broad
        if (isIpAddress(candidate)) return false

        var labelLength = 0
        for (character in candidate) {
            when {
                character == '.' -> {
                    if (labelLength == 0) return false // empty label, e.g. "a..b"
                    labelLength = 0
                }
                character in 'a'..'z' || character in '0'..'9' -> labelLength++
                character == '-' || character == '_' -> labelLength++
                else -> return false
            }
            if (labelLength > 63) return false
        }
        return labelLength > 0
    }

    /**
     * Rewrites an address literal into the form [java.net.InetAddress.getHostAddress]
     * produces, which is what the tunnel sees. Without this, a list entry of `2001:db8::1`
     * would never match the relay's `2001:db8:0:0:0:0:0:1`.
     */
    fun canonicalAddress(literal: String): String? = try {
        // For a literal this parses rather than resolving, so it never touches the network.
        java.net.InetAddress.getByName(literal).hostAddress
    } catch (error: java.net.UnknownHostException) {
        null
    }

    private fun isIpAddress(candidate: String): Boolean {
        if (candidate.isEmpty()) return false
        if (candidate.contains(':')) return true // IPv6, including "::"

        val parts = candidate.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' }
        }
    }
}
