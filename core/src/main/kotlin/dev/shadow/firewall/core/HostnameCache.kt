package dev.shadow.firewall.core

/**
 * Maps IP addresses back to the hostname an app looked up, populated by sniffing DNS
 * responses as they pass through the tunnel.
 *
 * Without this the traffic log would only ever show bare addresses, and domain rules could
 * not be applied to connections that skip a fresh lookup.
 */
class HostnameCache(
    private val maxEntries: Int = 4096,
    private val minimumTtlMillis: Long = 60_000,
    private val maximumTtlMillis: Long = 6 * 60 * 60 * 1000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry(val hostname: String, val expiresAtMillis: Long)

    private val entries = object : LinkedHashMap<String, Entry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>): Boolean =
            size > maxEntries
    }

    /** Records that [address] resolved from [hostname], honouring the record's TTL. */
    @Synchronized
    fun put(address: String, hostname: String, ttlSeconds: Long) {
        val name = hostname.trimEnd('.').lowercase()
        if (name.isEmpty()) return
        val ttl = (ttlSeconds * 1000).coerceIn(minimumTtlMillis, maximumTtlMillis)
        entries[address] = Entry(name, clock() + ttl)
    }

    @Synchronized
    fun get(address: String): String? {
        val entry = entries[address] ?: return null
        if (entry.expiresAtMillis <= clock()) {
            entries.remove(address)
            return null
        }
        return entry.hostname
    }

    @Synchronized
    fun size(): Int = entries.size

    @Synchronized
    fun clear() = entries.clear()

    /** Feeds every A/AAAA record of a DNS response into the cache. */
    fun record(message: Dns.Message) {
        if (!message.isResponse) return
        val queried = message.queryName ?: return
        for (answer in message.answers) {
            val address = answer.address ?: continue
            // Attribute the address to the name the app actually asked for, not the CNAME
            // target, so domain rules written against the visible name still apply.
            put(address.hostAddress ?: continue, queried, answer.ttlSeconds)
        }
    }
}
