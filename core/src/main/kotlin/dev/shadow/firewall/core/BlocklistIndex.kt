package dev.shadow.firewall.core

/**
 * One subscribed blocklist, ready to answer lookups.
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
) {
    val size: Int get() = blocked.size + blockedAddresses.size

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
 * Every enabled blocklist, consulted on each new connection whose hostname we know.
 *
 * Lists are kept separate rather than merged into one set so the traffic log can say which
 * list blocked a connection. With a handful of lists that is a handful of binary searches,
 * which is nothing next to the uid lookup happening on the same code path.
 */
class BlocklistIndex(val lists: List<Blocklist>) {

    val totalEntries: Int = lists.sumOf { it.size }

    val isEmpty: Boolean get() = lists.isEmpty()

    /** True when any list carries address rules, so the address check can be skipped. */
    val hasAddressRules: Boolean = lists.any { !it.blockedAddresses.isEmpty }

    /** The first list that blocks [host], or null if none does. */
    fun match(host: String): Blocklist? {
        if (lists.isEmpty()) return null
        for (list in lists) {
            if (list.blocks(host)) return list
        }
        return null
    }

    /** The first list that blocks the literal destination [address], or null. */
    fun matchAddress(address: String): Blocklist? {
        if (!hasAddressRules) return null
        for (list in lists) {
            if (list.blocksAddress(address)) return list
        }
        return null
    }

    companion object {
        val EMPTY = BlocklistIndex(emptyList())
    }
}
