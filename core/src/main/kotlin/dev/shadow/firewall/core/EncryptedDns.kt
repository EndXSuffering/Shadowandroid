package dev.shadow.firewall.core

/**
 * Encrypted DNS is the main reason a domain blocklist quietly stops working on Android.
 *
 * Since Android 9 the Private DNS setting defaults to "Automatic", which silently upgrades
 * lookups to DNS-over-TLS on port 853 whenever the network's resolver supports it — and the
 * common resolvers all do. Chrome and Firefox go further and use DNS-over-HTTPS to a provider
 * of their own. In either case the query never appears on port 53, so a filter watching port
 * 53 sees nothing at all and blocks nothing, without any sign that it has stopped working.
 *
 * The standard answer, and what every no-root blocker does, is to refuse the encrypted
 * transport so the resolver falls back to cleartext, where the query can be filtered.
 */
object EncryptedDns {

    /** DNS-over-TLS, and DNS-over-QUIC on the UDP side of the same number. */
    const val TLS_PORT = 853

    /**
     * Hostnames apps resolve to *find* their DoH endpoint. Refusing these sends a browser
     * back to the system resolver.
     *
     * This only covers name-based bootstrap. A client that ships hard-coded addresses for its
     * provider is not affected, so this narrows the hole rather than closing it.
     */
    private val PROVIDERS: Set<String> = setOf(
        // Google
        "dns.google",
        "dns.google.com",
        // Cloudflare
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "chrome.cloudflare-dns.com",
        "security.cloudflare-dns.com",
        "family.cloudflare-dns.com",
        "one.one.one.one",
        // Quad9
        "dns.quad9.net",
        "dns9.quad9.net",
        "dns10.quad9.net",
        "dns11.quad9.net",
        // OpenDNS
        "doh.opendns.com",
        "doh.familyshield.opendns.com",
        // Others in common use
        "dns.nextdns.io",
        "doh.cleanbrowsing.org",
        "dns.adguard.com",
        "dns.adguard-dns.com",
        "doh.dns.sb",
        "dns.alidns.com",
        "doh.pub",
        "dot.pub",
    )

    /** True when [hostname] is a known DoH bootstrap name, or a subdomain of one. */
    fun isProviderHostname(hostname: String): Boolean =
        RuleEngine.matches(hostname, PROVIDERS)

    /** True for a port carrying DNS-over-TLS or DNS-over-QUIC. */
    fun isEncryptedTransportPort(port: Int): Boolean = port == TLS_PORT

    /** Exposed so the settings screen can say exactly what is covered. */
    val providerCount: Int get() = PROVIDERS.size
}
