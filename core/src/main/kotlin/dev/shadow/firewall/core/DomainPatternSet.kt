package dev.shadow.firewall.core

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * One blocklist rule that carries a `*`, such as `||ads-*.v.ssp.yahoo.com^`.
 *
 * These cannot go in a [DomainHashSet], which answers exact and suffix matches only, so they
 * are kept separately and matched by pattern. They are rare — a few hundred across every list
 * this app ships — but they are not unimportant: ad networks spread a rotating pool of hosts
 * across one wildcard rule precisely so that a single name cannot be blocked. Dropping them
 * meant a page's ads were blocked or not depending on which host in the pool it happened to
 * pick, which looks like the firewall working intermittently.
 */
class DomainPattern private constructor(
    /** The rule as written, for the traffic log. */
    val source: String,
    /**
     * The literal text after the final `*`. A host that does not end with this cannot match,
     * and checking that first is far cheaper than running the expression.
     */
    private val requiredSuffix: String,
    private val regex: Regex,
) {

    fun matches(host: String): Boolean {
        if (requiredSuffix.isNotEmpty() && !host.endsWith(requiredSuffix)) return false
        return regex.matches(host)
    }

    override fun toString(): String = source

    companion object {
        /**
         * The shortest literal text a pattern may have. A pattern is only as safe as the parts
         * of it that are not wildcards: `*.com` would take out a third of the internet, so
         * anything that thin is refused rather than approximated.
         */
        private const val MIN_LITERAL_LENGTH = 6

        /**
         * Compiles a wildcard rule, or returns null if it is too broad to trust.
         *
         * `*` is treated as AdGuard treats it — any run of characters, dots included — and the
         * whole host must match, with subdomains of a match also matching, exactly as a plain
         * `||host^` rule covers its subdomains.
         */
        fun compile(rule: String): DomainPattern? {
            val pattern = rule.trim().lowercase().trimEnd('.')
            if (pattern.isEmpty() || '*' !in pattern) return null
            // A hostname has none of these; their presence means this was a URL or regex rule
            // that earlier parsing should have rejected.
            if (pattern.any { it == '/' || it == ':' || it == '?' || it == '@' || it.isWhitespace() }) {
                return null
            }

            val literal = pattern.replace("*", "")
            if (literal.length < MIN_LITERAL_LENGTH || '.' !in literal) return null

            val expression = StringBuilder("^(?:.*\\.)?")
            for (part in pattern.split('*').withIndex()) {
                if (part.index > 0) expression.append(".*")
                expression.append(Regex.escape(part.value))
            }
            expression.append('$')

            val compiled = try {
                Regex(expression.toString())
            } catch (invalid: IllegalArgumentException) {
                return null
            }
            return DomainPattern(pattern, pattern.substringAfterLast('*'), compiled)
        }
    }
}

/**
 * The wildcard rules from one list, checked only after its hash sets have missed.
 *
 * Kept as a plain list and scanned linearly. That is affordable because this runs once per DNS
 * query rather than per packet, because there are only a few hundred patterns in total, and
 * because [DomainPattern.matches] rejects almost all of them on a string comparison before any
 * expression is evaluated.
 */
class DomainPatternSet(private val patterns: List<DomainPattern>) {

    val size: Int get() = patterns.size

    val isEmpty: Boolean get() = patterns.isEmpty()

    /** The first pattern [host] matches, or null. */
    fun match(host: String): DomainPattern? {
        for (pattern in patterns) {
            if (pattern.matches(host)) return pattern
        }
        return null
    }

    fun contains(host: String): Boolean = match(host) != null

    fun writeTo(stream: OutputStream) {
        val out = DataOutputStream(stream)
        out.writeInt(MAGIC)
        out.writeInt(FORMAT_VERSION)
        out.writeInt(patterns.size)
        for (pattern in patterns) out.writeUTF(pattern.source)
        out.flush()
    }

    companion object {
        private const val MAGIC = 0x53465057 // "SFPW"
        private const val FORMAT_VERSION = 1

        /**
         * A cap on how many patterns one list may contribute, so that a future list made
         * mostly of wildcards cannot quietly turn every DNS lookup into a long scan.
         */
        const val MAX_PATTERNS = 20_000

        val EMPTY = DomainPatternSet(emptyList())

        fun build(rules: Iterable<String>): DomainPatternSet {
            val compiled = ArrayList<DomainPattern>()
            for (rule in rules) {
                if (compiled.size >= MAX_PATTERNS) break
                compile(rule)?.let { compiled += it }
            }
            return if (compiled.isEmpty()) EMPTY else DomainPatternSet(compiled)
        }

        fun compile(rule: String): DomainPattern? = DomainPattern.compile(rule)

        fun readFrom(stream: InputStream): DomainPatternSet {
            val input = DataInputStream(stream)
            if (input.readInt() != MAGIC) throw IOException("not a pattern index")
            val version = input.readInt()
            if (version != FORMAT_VERSION) throw IOException("unsupported pattern version $version")
            val count = input.readInt()
            if (count < 0 || count > MAX_PATTERNS) throw IOException("implausible pattern count $count")
            val patterns = ArrayList<DomainPattern>(count)
            repeat(count) {
                DomainPattern.compile(input.readUTF())?.let { patterns += it }
            }
            return if (patterns.isEmpty()) EMPTY else DomainPatternSet(patterns)
        }
    }
}
