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
            val decision = subject.decide(chromeUid, NetworkType.WIFI, host, false)
            assertEquals(Verdict.BLOCK, decision.verdict, host)
            assertEquals(BlockReason.DOMAIN_BLOCKLIST, decision.reason)
        }
    }

    @Test
    fun `domain blocklist does not match a lookalike suffix`() {
        val subject = engine(RuleSet(blockedDomains = setOf("example.com")))
        // "notexample.com" ends with the entry as a string but is a different domain.
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "notexample.com", false).verdict)
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "example.com.evil.net", false).verdict)
    }

    @Test
    fun `allow list punches a hole in a blocked domain`() {
        val subject = engine(
            RuleSet(
                blockedDomains = setOf("example.com"),
                allowedDomains = setOf("cdn.example.com"),
            ),
        )
        assertEquals(Verdict.BLOCK, subject.decide(chromeUid, NetworkType.WIFI, "ads.example.com", false).verdict)
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "cdn.example.com", false).verdict)
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "img.cdn.example.com", false).verdict)
    }

    @Test
    fun `domain matching ignores case and a trailing root dot`() {
        val subject = engine(RuleSet(blockedDomains = setOf("tracker.io")))
        assertEquals(Verdict.BLOCK, subject.decide(chromeUid, NetworkType.WIFI, "API.Tracker.IO.", false).verdict)
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
        // The domain list still applies to apps with no rule of their own.
        assertEquals(BlockReason.DOMAIN_BLOCKLIST, subject.decide(chromeUid, NetworkType.WIFI, "ads.example.com", false).reason)
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
    fun `a subscribed list blocks a domain and names itself`() {
        val decision = engineWithLists().decide(chromeUid, NetworkType.WIFI, "ad.doubleclick.net", false)
        assertEquals(Verdict.BLOCK, decision.verdict)
        assertEquals(BlockReason.SUBSCRIBED_LIST, decision.reason)
        assertEquals("Test ad list", decision.source)
    }

    @Test
    fun `a list's own exception is honoured`() {
        val subject = engineWithLists()
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "safe.doubleclick.net", false).verdict)
    }

    @Test
    fun `the user allowlist overrides a subscribed list`() {
        val subject = engineWithLists(RuleSet(allowedDomains = setOf("doubleclick.net")))
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "ad.doubleclick.net", false).verdict)
    }

    @Test
    fun `the master switch disables subscribed lists without discarding them`() {
        val subject = engineWithLists(RuleSet(useBlocklists = false))
        assertEquals(Verdict.ALLOW, subject.decide(chromeUid, NetworkType.WIFI, "ad.doubleclick.net", false).verdict)
        assertEquals(1, subject.blocklists.lists.size)
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
