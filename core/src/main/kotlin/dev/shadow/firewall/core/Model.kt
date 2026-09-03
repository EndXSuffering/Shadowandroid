package dev.shadow.firewall.core

/** Transport protocol numbers as they appear in the IP header. */
object IpProto {
    const val ICMP = 1
    const val TCP = 6
    const val UDP = 17
    const val ICMPV6 = 58

    fun name(protocol: Int): String = when (protocol) {
        ICMP -> "ICMP"
        TCP -> "TCP"
        UDP -> "UDP"
        ICMPV6 -> "ICMPv6"
        else -> "IP/$protocol"
    }
}

/** Which underlying transport the device is using right now. */
enum class NetworkType { WIFI, MOBILE, OTHER }

enum class Verdict { ALLOW, BLOCK }

enum class BlockReason {
    /** Not blocked. */
    NONE,

    /** An explicit per-app rule blocked this network type. */
    APP_RULE,

    /** No explicit rule, and the default policy is "block". */
    DEFAULT_POLICY,

    /** The resolved hostname matched the user's own domain blocklist. */
    DOMAIN_BLOCKLIST,

    /** The resolved hostname matched one of the subscribed ad or malware lists. */
    SUBSCRIBED_LIST,

    /** IPv6 is switched off, so v6 flows are dropped to force a v4 fallback. */
    IPV6_DISABLED,

    /** Encrypted DNS refused so lookups fall back to a transport that can be filtered. */
    ENCRYPTED_DNS,

    /**
     * The app is routed through Tor and this flow is something Tor cannot carry. Tor is a TCP
     * relay network, so UDP has nowhere to go; dropping it is the only honest answer, because
     * sending it directly would leak around the very thing the user asked for.
     */
    TOR_UNSUPPORTED,
}

/** Identifies one transport flow inside the tunnel. */
data class FlowKey(
    val protocol: Int,
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String,
    val destinationPort: Int,
)

/**
 * One entry in the traffic log. Byte counters are updated by replacing the entry, so the
 * type stays immutable and safe to hand to the UI thread.
 */
data class ConnectionEvent(
    val id: Long,
    val startedAtMillis: Long,
    val updatedAtMillis: Long,
    val uid: Int,
    val packageName: String?,
    val appLabel: String?,
    val protocol: Int,
    val destinationAddress: String,
    val destinationPort: Int,
    val hostname: String?,
    val network: NetworkType,
    val verdict: Verdict,
    val reason: BlockReason,
    /** Which subscribed list matched, when the reason is [BlockReason.SUBSCRIBED_LIST]. */
    val ruleSource: String? = null,
    /** True when the connection was handed to Tor rather than dialled directly. */
    val viaTor: Boolean = false,
    val bytesOut: Long = 0,
    val bytesIn: Long = 0,
) {
    /** Hostname when we know it, otherwise the bare address. */
    val displayTarget: String get() = hostname ?: destinationAddress
}
