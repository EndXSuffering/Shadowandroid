package dev.shadow.firewall.core

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * A large set of blocked domains, stored as sorted 64-bit hashes rather than strings.
 *
 * The published blocklists are big: the AdGuard DNS filter is about 155,000 domains and
 * HaGeZi's threat feed is over two million. As a `HashSet<String>` two million domains cost
 * roughly 180 MB, which no phone will tolerate for a background service. As sorted hashes the
 * same list is 16 MB, and lookups are a binary search instead of a hash probe.
 *
 * The trade-off is that a hash collision blocks a domain that is not on the list. At two
 * million entries in a 64-bit space the chance of any collision existing at all is about one
 * in ten million — far below the false-positive rate of the lists themselves — but it is not
 * zero, and it fails silently. That is why the user's own allowlist is always checked first.
 */
class DomainHashSet private constructor(private val hashes: LongArray) {

    val size: Int get() = hashes.size

    val isEmpty: Boolean get() = hashes.isEmpty()

    /**
     * True when [host] or any of its parent domains is in the set, so an entry for
     * `example.com` also covers `ads.example.com`.
     */
    fun contains(host: String): Boolean {
        if (hashes.isEmpty()) return false
        val name = RuleEngine.normalise(host)
        if (name.isEmpty()) return false

        if (containsExact(name)) return true
        var index = name.indexOf('.')
        while (index in 0 until name.length - 1) {
            if (containsExact(name.substring(index + 1))) return true
            index = name.indexOf('.', index + 1)
        }
        return false
    }

    /** True when exactly this domain is present; no parent-domain walk. */
    fun containsExact(domain: String): Boolean =
        hashes.binarySearch(hash(domain)) >= 0

    fun writeTo(stream: OutputStream) {
        val out = DataOutputStream(stream)
        out.writeInt(MAGIC)
        out.writeInt(FORMAT_VERSION)
        out.writeInt(hashes.size)
        for (value in hashes) out.writeLong(value)
        out.flush()
    }

    /**
     * Accumulates hashes without ever holding the domain strings.
     *
     * Parsing HaGeZi's two-million-entry feed into a `List<String>` first would peak around
     * 200 MB and get the process killed; feeding this builder line by line peaks at the
     * 17 MB the hashes themselves need.
     */
    class Builder(initialCapacity: Int = 1024) {
        private var hashes = LongArray(initialCapacity.coerceAtLeast(16))
        private var count = 0

        val size: Int get() = count

        fun add(domain: String) {
            val name = RuleEngine.normalise(domain)
            if (name.isEmpty()) return
            if (count == hashes.size) hashes = hashes.copyOf(hashes.size * 2)
            hashes[count++] = hash(name)
        }

        fun addAll(domains: Iterable<String>) {
            for (domain in domains) add(domain)
        }

        fun build(): DomainHashSet {
            if (count == 0) return EMPTY
            val exact = hashes.copyOf(count)
            exact.sort()
            return deduplicate(exact)
        }
    }

    companion object {
        /** "SFBL", so a truncated or foreign file is rejected rather than misread. */
        private const val MAGIC = 0x5346424C
        private const val FORMAT_VERSION = 1

        private const val FNV_OFFSET_BASIS = -0x340d631b7bdddcdbL
        private const val FNV_PRIME = 0x100000001b3L

        val EMPTY = DomainHashSet(LongArray(0))

        fun build(domains: Iterable<String>): DomainHashSet {
            val collected = ArrayList<Long>()
            for (domain in domains) {
                val name = RuleEngine.normalise(domain)
                if (name.isNotEmpty()) collected.add(hash(name))
            }
            if (collected.isEmpty()) return EMPTY

            val array = LongArray(collected.size)
            for (i in collected.indices) array[i] = collected[i]
            array.sort()

            // Blocklists overlap heavily, both internally and with each other.
            return deduplicate(array)
        }

        fun readFrom(stream: InputStream): DomainHashSet {
            val input = DataInputStream(stream)
            if (input.readInt() != MAGIC) throw IOException("not a blocklist index")
            val version = input.readInt()
            if (version != FORMAT_VERSION) throw IOException("unsupported index version $version")

            val count = input.readInt()
            if (count < 0 || count > MAX_ENTRIES) throw IOException("implausible entry count $count")

            val hashes = LongArray(count)
            for (i in 0 until count) hashes[i] = input.readLong()
            // The file should already be sorted, but a corrupt one would break binary search
            // in a way that silently returns wrong answers, so verify rather than trust.
            for (i in 1 until count) {
                if (hashes[i] < hashes[i - 1]) throw IOException("index is not sorted")
            }
            return DomainHashSet(hashes)
        }

        /** FNV-1a, 64-bit. Chosen for speed and a good spread over short ASCII strings. */
        fun hash(domain: String): Long {
            var value = FNV_OFFSET_BASIS
            for (character in domain) {
                value = value xor (character.code.toLong() and 0xFF)
                value *= FNV_PRIME
            }
            return value
        }

        private fun deduplicate(sorted: LongArray): DomainHashSet {
            var unique = 0
            for (i in sorted.indices) {
                if (i == 0 || sorted[i] != sorted[i - 1]) unique++
            }
            if (unique == sorted.size) return DomainHashSet(sorted)

            val result = LongArray(unique)
            var next = 0
            for (i in sorted.indices) {
                if (i == 0 || sorted[i] != sorted[i - 1]) result[next++] = sorted[i]
            }
            return DomainHashSet(result)
        }

        /** Guards against a corrupt header asking us to allocate an absurd array. */
        private const val MAX_ENTRIES = 20_000_000
    }
}
