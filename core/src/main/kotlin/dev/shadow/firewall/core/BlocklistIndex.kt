package dev.shadow.firewall.core

/**
 * One subscribed list, ready to answer lookups.
 *
 * [allowed] holds the list's own exception rules (`@@||ad.example.com^`). They are the list
 * author saying "this one is a false positive", so they win over [blocked] within this list.
 */
class Blocklist(
    val id: String,
    val title: String,
    val blocked: DomainHashSet,
    val allowed: DomainHashSet = DomainHashSet.EMPTY,
    /** Literal IP addresses, matched exactly against a connection's destination. */
    val blockedAddresses: DomainHashSet = DomainHashSet.EMPTY,
    /**
     * True for a list that exists only to *un*-block things — a maintained set of exceptions
     * covering the domains that aggressive tracker lists are known to break, such as the
     * redirectors behind shopping and referral links. Its exceptions apply across every
     * subscribed list rather than only to its own entries.
     */
    val isAllowlist: Boolean = false,
) {
    val size: Int get() = if (isAllowlist) allowed.size else blocked.size + blockedAddresses.size

    fun blocks(host: String): Boolean =
        blocked.contains(host) && !allowed.contains(host)

    /**
     * Matches a destination IP against the list's address rules. Unlike [blocks] this needs
     * an exact match — an address has no parent to inherit from.
     */
    fun blocksAddress(address: String): Boolean =
        !blockedAddresses.isEmpty && blockedAddresses.containsExact(address)
}

/**
 * Every enabled list, consulted on each DNS query and each new connection.
 *
 * Lists are kept separate rather than merged into one set so the traffic log can say which
 * list blocked a connection. With a handful of lists that is a handful of binary searches,
 * which is nothing next to the uid lookup happening on the same code path.
 */
class BlocklistIndex(val lists: List<Blocklist>) {

    private val allowlists: List<DomainHashSet> =
        lists.filter { it.isAllowlist }.map { it.allowed }.filter { !it.isEmpty }

    private val blocklists: List<Blocklist> = lists.filter { !it.isAllowlist }

    val totalEntries: Int = lists.sumOf { it.size }

    val isEmpty: Boolean get() = lists.isEmpty()

    /** True when any list carries address rules, so the address check can be skipped. */
    val hasAddressRules: Boolean = blocklists.any { !it.blockedAddresses.isEmpty }

    /**
     * True when a subscribed allowlist exempts [host]. Checked before anything blocks, which
     * is what lets a broad tracker list run without taking shopping links down with it.
     */
    fun isExempt(host: String): Boolean {
        for (allowlist in allowlists) {
            if (allowlist.contains(host)) return true
        }
        return false
    }

    /** The first list that blocks [host], or null if none does. */
    fun match(host: String): Blocklist? {
        if (blocklists.isEmpty()) return null
        if (isExempt(host)) return null
        for (list in blocklists) {
            if (list.blocks(host)) return list
        }
        return null
    }

    /** The first list that blocks the literal destination [address], or null. */
    fun matchAddress(address: String): Blocklist? {
        if (!hasAddressRules) return null
        for (list in blocklists) {
            if (list.blocksAddress(address)) return list
        }
        return null
    }

    companion object {
        val EMPTY = BlocklistIndex(emptyList())
    }
}
