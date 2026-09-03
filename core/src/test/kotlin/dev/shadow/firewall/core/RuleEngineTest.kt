package dev.shadow.firewall.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuleEngineTest {

    private val chromeUid = 10123
    private val gameUid = 10456

    private fun engine(rules: RuleSet) = RuleEngine(rules)

    @Test
    fun `allows everything when nothing is configured`() {
        val decision = engine(RuleSet()).decide(chromeUid, NetworkType.WIFI, null, isIpv6 = false)
        assertEquals(Verdict.ALLOW, decision.verdict)
        assertEquals(BlockReason.NONE, decision.reason)
    }

    @Test
    fun `per app rule blocks only the network it names`() {
        val rules = RuleSet().withAppRule(AppRule(gameUid, blockWifi = false, blockMobile = true))
        val subject = engine(rules)

        assertEquals(Verdict.ALLOW, subject.decide(gameUid, NetworkType.WIFI, null, false).verdict)

        val mobile = subject.decide(gameUid, NetworkType.MOBILE, null, false)
        assertEquals(Verdict.BLOCK, mobile.verdict)
        assertEquals(BlockReason.APP_RULE, mobile.reason)
    }

    @Test
    fun `other networks are blocked only when both toggles are off`() {
        val partial = engine(RuleSet().withAppRule(AppRule(gameUid, blockWifi = true, blockMobile = false)))
        assertEquals(Verdict.ALLOW, partial.decide(gameUid, NetworkType.OTHER, null, false).verdict)

        val full = engine(RuleSet().withAppRule(AppRule(gameUid, blockWifi = true, blockMobile = true)))
        assertEquals(Verdict.BLOCK, full.decide(gameUid, NetworkType.OTHER, null, false).verdict)
    }

    @Test
    fun `block by default denies apps without a rule`() {
        val subject = engine(RuleSet(blockByDefault = true))
        val decision = subject.decide(chromeUid, NetworkType.WIFI, null, false)
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.DEFAULT_POLICY, decision.reason)
    }

    @Test
    fun `block by default respects the allow list`() {
        val subject = engine(RuleSet(blockByDefault = true, allowedUids = setOf(chromeUid)))
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, null, false).verdict)
        assertEquals(Verdict.BLOCK, subject.decide(gameUid, NetworkType.WIFI, null, false).verdict)
    }

    @Test
    fun `an explicit permissive rule beats block by default`() {
        val rules = RuleSet(blockByDefault = true)
            .withAppRule(AppRule(chromeUid, blockWifi = false, blockMobile = true))
        val subject = engine(rules)

        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, null, false).verdict)
        assertEquals(Verdict.BLOCK, subject.decide(chromeUid, NetworkType.MOBILE, null, false).verdict)
    }

    @Test
    fun `domain blocklist matches subdomains`() {
        val subject = engine(RuleSet(blockedDomains = setOf("doubleclick.net")))

        for (host in listOf("doubleclick.net", "ad.doubleclick.net", "a.b.c.doubleclick.net")) {
            val decision = subject.decideHostname(host)
            assertEquals(Verdict.BLOCK, decision.verdict, host)
            assertEquals(BlockReason.DOMAIN_BLOCKLIST, decision.reason)
        }
    }

    @Test
    fun `domain blocklist does not match a lookalike suffix`() {
        val subject = engine(RuleSet(blockedDomains = setOf("example.com")))
        // "notexample.com" ends with the entry as a string but is a different domain.
        assertEquals(Verdict.ALLOW, subject.decideHostname("notexample.com").verdict)
        assertEquals(Verdict.ALLOW, subject.decideHostname("example.com.evil.net").verdict)
    }

    @Test
    fun `allow list punches a hole in a blocked domain`() {
        val subject = engine(
            RuleSet(
                blockedDomains = setOf("example.com"),
                allowedDomains = setOf("cdn.example.com"),
            ),
        )
        assertEquals(Verdict.BLOCK, subject.decideHostname("ads.example.com").verdict)
        assertEquals(Verdict.ALLOW, subject.decideHostname("cdn.example.com").verdict)
        assertEquals(Verdict.ALLOW, subject.decideHostname("img.cdn.example.com").verdict)
    }

    @Test
    fun `domain matching ignores case and a trailing root dot`() {
        val subject = engine(RuleSet(blockedDomains = setOf("tracker.io")))
        assertEquals(Verdict.BLOCK, subject.decideHostname("API.Tracker.IO.").verdict)
    }

    @Test
    fun `ipv6 is dropped when the toggle is on`() {
        val subject = engine(RuleSet(blockIpv6 = true))
        val decision = subject.decide(chromeUid, NetworkType.WIFI, null, isIpv6 = true)
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.IPV6_DISABLED, decision.reason)
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, null, isIpv6 = false).verdict)
    }

    @Test
    fun `app rules take priority over an unrelated domain rule`() {
        val rules = RuleSet(blockedDomains = setOf("ads.example.com"))
            .withAppRule(AppRule(gameUid, blockWifi = true, blockMobile = true))
        val subject = engine(rules)

        // Blocked by the app rule even though the host is not on the domain list.
        assertEquals(BlockReason.APP_RULE, subject.decide(gameUid, NetworkType.WIFI, "cdn.example.org", false).reason)
        // The domain list is enforced at query time rather than on the connection.
        assertEquals(BlockReason.DOMAIN_BLOCKLIST, subject.decideHostname("ads.example.com").reason)
    }

    @Test
    fun `setting an app back to its defaults removes the rule`() {
        val rules = RuleSet()
            .withAppRule(AppRule(gameUid, blockWifi = true, blockMobile = true))
            .withAppRule(AppRule(gameUid, blockWifi = false, blockMobile = false))
        assertTrue(rules.appRules.isEmpty())
        assertTrue(rules.ruleFor(gameUid).isDefault)
    }

    @Test
    fun `domain normalisation drops comments and blank entries`() {
        val parsed = RuleEngine.normaliseAll(listOf(" Ads.Example.COM. ", "", "   ", "# a comment", "b.net"))
        assertEquals(setOf("ads.example.com", "b.net"), parsed)
    }

    @Test
    fun `matching an empty blocklist is cheap and false`() {
        assertFalse(RuleEngine.matches("anything.example.com", emptySet()))
    }

    // ------------------------------------------------ subscribed lists

    private fun engineWithLists(rules: RuleSet = RuleSet()): RuleEngine {
        val list = Blocklist(
            id = "ads",
            title = "Test ad list",
            blocked = DomainHashSet.build(listOf("doubleclick.net", "tracker.example.org")),
            allowed = DomainHashSet.build(listOf("safe.doubleclick.net")),
            blockedAddresses = DomainHashSet.build(listOf("109.201.135.46")),
        )
        return RuleEngine(rules).apply { blocklists = BlocklistIndex(listOf(list)) }
    }

    @Test
    fun `a subscribed list blocks a looked-up domain and names itself`() {
        val decision = engineWithLists().decideHostname("ad.doubleclick.net")
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.SUBSCRIBED_LIST, decision.reason)
        assertEquals("Test ad list", decision.source)
    }

    @Test
    fun `a list's own exception is honoured`() {
        assertEquals(Verdict.ALLOW, engineWithLists().decideHostname("safe.doubleclick.net").verdict)
    }

    @Test
    fun `the user allowlist overrides a subscribed list`() {
        val subject = engineWithLists(RuleSet(allowedDomains = setOf("doubleclick.net")))
        assertEquals(Verdict.ALLOW, subject.decideHostname("ad.doubleclick.net").verdict)
    }

    @Test
    fun `the master switch disables subscribed lists without discarding them`() {
        val subject = engineWithLists(RuleSet(useBlocklists = false))
        assertEquals(Verdict.ALLOW, subject.decideHostname("ad.doubleclick.net").verdict)
        assertEquals(1, subject.blocklists.lists.size)
    }

    // ----------------------------------------- encrypted dns

    @Test
    fun `a doh bootstrap name is refused so lookups fall back to cleartext`() {
        val decision = engine(RuleSet()).decideHostname("mozilla.cloudflare-dns.com")
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.ENCRYPTED_DNS, decision.reason)
    }

    @Test
    fun `subdomains of a doh provider are covered`() {
        assertEquals(Verdict.BLOCK, engine(RuleSet()).decideHostname("foo.dns.nextdns.io").verdict)
    }

    @Test
    fun `an ordinary hostname is not mistaken for a resolver`() {
        assertEquals(Verdict.ALLOW, engine(RuleSet()).decideHostname("dns.example.com").verdict)
        assertEquals(Verdict.ALLOW, engine(RuleSet()).decideHostname("google.com").verdict)
    }

    @Test
    fun `turning the setting off leaves encrypted dns alone`() {
        val subject = engine(RuleSet(blockEncryptedDns = false))
        assertEquals(Verdict.ALLOW, subject.decideHostname("dns.google").verdict)
    }

    @Test
    fun `the user allowlist overrides the encrypted dns rule`() {
        val subject = engine(RuleSet(allowedDomains = setOf("dns.google")))
        assertEquals(Verdict.ALLOW, subject.decideHostname("dns.google").verdict)
    }

    @Test
    fun `the dot port is recognised and ordinary ports are not`() {
        assertTrue(EncryptedDns.isEncryptedTransportPort(853))
        assertFalse(EncryptedDns.isEncryptedTransportPort(443))
        assertFalse(EncryptedDns.isEncryptedTransportPort(53))
    }

    // ------------------------------------------- tunnel bypass

    @Test
    fun `bypass is recorded per package and can be removed`() {
        val rules = RuleSet().withBypass("com.example.messages", true)
        assertTrue(rules.isBypassed("com.example.messages"))
        assertFalse(rules.isBypassed("com.example.other"))
        assertFalse(rules.isBypassed(null))

        assertTrue(rules.withBypass("com.example.messages", false).bypassedPackages.isEmpty())
    }

    @Test
    fun `bypass is not a verdict the engine reaches`() {
        // A bypassed app is excluded at the interface, so its packets never arrive. The
        // engine must not start second-guessing that, or a package could end up both
        // outside the tunnel and blocked inside it.
        val rules = RuleSet().withBypass("com.example.messages", true)
            .withAppRule(AppRule(gameUid, blockWifi = true, blockMobile = true))
        val subject = engine(rules)

        assertEquals(Verdict.BLOCK, subject.decide(gameUid, NetworkType.WIFI, null, false).verdict)
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, null, false).verdict)
    }

    // ------------------------------------------- tor routing

    @Test
    fun `tor routing and bypass cannot both be set on one package`() {
        // They contradict each other: an excluded app's packets never reach the relay, so
        // there is nothing left to hand to Tor. Setting either has to clear the other.
        val routed = RuleSet().withBypass("com.example.browser", true)
            .withTorRouting("com.example.browser", true)
        assertTrue(routed.isTorRouted("com.example.browser"))
        assertFalse(routed.isBypassed("com.example.browser"))

        val bypassed = routed.withBypass("com.example.browser", true)
        assertTrue(bypassed.isBypassed("com.example.browser"))
        assertFalse(bypassed.isTorRouted("com.example.browser"))
    }

    @Test
    fun `usesTor is only true while something is routed`() {
        assertFalse(RuleSet().usesTor)
        val rules = RuleSet().withTorRouting("com.example.browser", true)
        assertTrue(rules.usesTor)
        assertFalse(rules.withTorRouting("com.example.browser", false).usesTor)
    }

    @Test
    fun `udp from a routed app is dropped rather than sent around tor`() {
        val subject = engine(RuleSet()).apply { torUids = setOf(chromeUid) }

        val quic = subject.decide(
            uid = chromeUid,
            network = NetworkType.WIFI,
            hostname = null,
            isIpv6 = false,
            protocol = IpProto.UDP,
            destinationPort = 443,
        )
        assertEquals(Verdict.BLOCK, quic.verdict)
        assertEquals(BlockReason.TOR_UNSUPPORTED, quic.reason)
    }

    @Test
    fun `a routed app can still look names up`() {
        // DNS is answered by the system resolver rather than the app's own socket, and
        // dropping it would leave the app unable to resolve anything at all.
        val subject = engine(RuleSet()).apply { torUids = setOf(chromeUid) }

        val lookup = subject.decide(
            uid = chromeUid,
            network = NetworkType.WIFI,
            hostname = null,
            isIpv6 = false,
            protocol = IpProto.UDP,
            destinationPort = Dns.PORT,
        )
        assertEquals(Verdict.ALLOW, lookup.verdict)

        val tcp = subject.decide(
            uid = chromeUid,
            network = NetworkType.WIFI,
            hostname = null,
            isIpv6 = false,
            protocol = IpProto.TCP,
            destinationPort = 443,
        )
        assertEquals(Verdict.ALLOW, tcp.verdict)
    }

    @Test
    fun `udp is untouched for apps that are not routed`() {
        val subject = engine(RuleSet()).apply { torUids = setOf(chromeUid) }
        val decision = subject.decide(
            uid = gameUid,
            network = NetworkType.WIFI,
            hostname = null,
            isIpv6 = false,
            protocol = IpProto.UDP,
            destinationPort = 443,
        )
        assertEquals(Verdict.ALLOW, decision.verdict)
    }

    @Test
    fun `an allow rule does not override what tor cannot carry`() {
        // The UDP drop is a capability limit, not a policy, so an explicit per-app rule that
        // permits this network must not turn it back on.
        val rules = RuleSet().withAppRule(AppRule(chromeUid, blockWifi = false, blockMobile = true))
        val subject = engine(rules).apply { torUids = setOf(chromeUid) }

        val decision = subject.decide(
            uid = chromeUid,
            network = NetworkType.WIFI,
            hostname = null,
            isIpv6 = false,
            protocol = IpProto.UDP,
            destinationPort = 443,
        )
        assertEquals(BlockReason.TOR_UNSUPPORTED, decision.reason)
    }

    // ------------------------------------ subscribed allowlists

    private fun engineWithAllowlist(): RuleEngine {
        val trackers = Blocklist(
            id = "trackers",
            title = "Aggressive tracker list",
            blocked = DomainHashSet.build(listOf("go.redirectingat.com", "tracker.example.org")),
        )
        // A referral allowlist ships as @@ exceptions and must override every other list,
        // not just its own entries — that is what keeps shopping links working under a
        // broad tracker list.
        val referral = Blocklist(
            id = "referral",
            title = "Referral exceptions",
            blocked = DomainHashSet.EMPTY,
            allowed = DomainHashSet.build(listOf("go.redirectingat.com")),
            isAllowlist = true,
        )
        return RuleEngine().apply { blocklists = BlocklistIndex(listOf(trackers, referral)) }
    }

    @Test
    fun `a subscribed allowlist overrides a different list's block`() {
        assertEquals(Verdict.ALLOW, engineWithAllowlist().decideHostname("go.redirectingat.com").verdict)
    }

    @Test
    fun `the allowlist does not exempt everything else on that list`() {
        assertEquals(Verdict.BLOCK, engineWithAllowlist().decideHostname("tracker.example.org").verdict)
    }

    @Test
    fun `an allowlist covers subdomains of its entries`() {
        assertEquals(Verdict.ALLOW, engineWithAllowlist().decideHostname("a.go.redirectingat.com").verdict)
    }

    @Test
    fun `an allowlist contributes its exceptions rather than its blocks to the total`() {
        val index = engineWithAllowlist().blocklists
        // Two blocked domains plus one exception.
        assertEquals(3, index.totalEntries)
        assertTrue(index.isExempt("go.redirectingat.com"))
        assertFalse(index.isExempt("tracker.example.org"))
    }

    // -------------------------------- shared-address regressions

    @Test
    fun `a connection is never blocked because of a reverse-looked-up hostname`() {
        // The bug this guards: claude.ai and a blocked tracker share a Cloudflare address,
        // so the IP-to-name cache hands the connection the tracker's name. Acting on that
        // took down claude.ai, Amazon and RCS messaging on a real device.
        val subject = engineWithLists()
        val decision = subject.decide(
            chromeUid, NetworkType.WIFI,
            hostname = "tracker.example.org", // on the list, but only a reverse guess
            isIpv6 = false,
            destinationAddress = "104.18.0.1",
        )
        assertEquals(Verdict.ALLOW, decision.verdict)
    }

    @Test
    fun `the same name still blocks when it comes from an actual query`() {
        assertEquals(Verdict.BLOCK, engineWithLists().decideHostname("tracker.example.org").verdict)
    }

    @Test
    fun `a user-blocked domain is also not enforced from a reverse lookup`() {
        val subject = engine(RuleSet(blockedDomains = setOf("tracker.example.org")))
        assertEquals(
            Verdict.ALLOW,
            subject.decide(chromeUid, NetworkType.WIFI, "tracker.example.org", false, "104.18.0.1").verdict,
        )
        assertEquals(Verdict.BLOCK, subject.decideHostname("tracker.example.org").verdict)
    }

    @Test
    fun `an address rule blocks even when no hostname is known`() {
        val decision = engineWithLists()
            .decide(chromeUid, NetworkType.WIFI, null, false, destinationAddress = "109.201.135.46")
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.SUBSCRIBED_LIST, decision.reason)
    }

    @Test
    fun `an unlisted address is allowed`() {
        val decision = engineWithLists()
            .decide(chromeUid, NetworkType.WIFI, null, false, destinationAddress = "93.184.216.34")
        assertEquals(Verdict.ALLOW, decision.verdict)
    }

    @Test
    fun `an address rule still fires when the reverse name is a blocked one`() {
        // Address rules are literal IPs from the list, so they are exact and stay in force
        // even though the reverse hostname beside them is untrustworthy.
        val decision = engineWithLists().decide(
            chromeUid, NetworkType.WIFI, "tracker.example.org", false, "109.201.135.46",
        )
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.SUBSCRIBED_LIST, decision.reason)
    }

    @Test
    fun `the user allowlist also overrides an address rule`() {
        val subject = engineWithLists(RuleSet(allowedDomains = setOf("known.example.com")))
        val decision = subject.decide(
            chromeUid, NetworkType.WIFI, "known.example.com", false,
            destinationAddress = "109.201.135.46",
        )
        assertEquals(Verdict.ALLOW, decision.verdict)
    }

    @Test
    fun `an app rule still beats a subscribed list allowing the host`() {
        val subject = engineWithLists(
            RuleSet().withAppRule(AppRule(gameUid, blockWifi = true, blockMobile = true)),
        )
        assertEquals(BlockReason.APP_RULE, subject.decide(gameUid, NetworkType.WIFI, "example.com", false).reason)
    }
}
