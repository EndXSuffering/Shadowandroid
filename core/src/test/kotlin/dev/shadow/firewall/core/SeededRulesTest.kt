package dev.shadow.firewall.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SeededRulesTest {

    @Test
    fun `a fresh install gets every seeded domain`() {
        val result = SeededRules.apply(emptySet(), emptySet(), appliedVersion = 0)
        assertTrue("gam.mail.yahoosandbox.net" in result.blocked)
        assertTrue("pbs.yahoo.com" in result.blocked)
        assertTrue("bm.paypal.com" in result.allowed)
        assertTrue("validate.perfdrive.com" in result.allowed)
        assertEquals(SeededRules.LATEST, result.version)
    }

    @Test
    fun `what the user already had is kept`() {
        val result = SeededRules.apply(setOf("example.com"), setOf("keep.example.org"), 0)
        assertTrue("example.com" in result.blocked)
        assertTrue("keep.example.org" in result.allowed)
    }

    @Test
    fun `a deleted seed is not put back`() {
        // Seeded, then the user removed pbs.yahoo.com. Running again at the stored version
        // must leave that choice alone.
        val seeded = SeededRules.apply(emptySet(), emptySet(), 0)
        val afterDeletion = seeded.blocked - "pbs.yahoo.com"
        val again = SeededRules.apply(afterDeletion, seeded.allowed, seeded.version)
        assertFalse("pbs.yahoo.com" in again.blocked)
        assertFalse(again.changed(afterDeletion, seeded.allowed))
    }

    @Test
    fun `a seeded allow never overrides a domain the user deliberately blocked`() {
        // Allowed domains win over everything, so seeding one on top of the user's own block
        // would silently reverse their choice.
        val result = SeededRules.apply(setOf("bm.paypal.com"), emptySet(), 0)
        assertTrue("bm.paypal.com" in result.blocked)
        assertFalse("bm.paypal.com" in result.allowed)
    }

    @Test
    fun `a seeded block is skipped if the user allowed it`() {
        val result = SeededRules.apply(emptySet(), setOf("pbs.yahoo.com"), 0)
        assertFalse("pbs.yahoo.com" in result.blocked)
        assertTrue("pbs.yahoo.com" in result.allowed)
    }

    @Test
    fun `a later release adds only its own new entries`() {
        val releases = listOf(
            SeededRules.Release(blocked = listOf("one.example.com")),
            SeededRules.Release(blocked = listOf("two.example.com")),
        )
        // Release 1 applied, then deleted by the user; release 2 arrives in an update.
        val result = SeededRules.apply(emptySet(), emptySet(), appliedVersion = 1, releases = releases)
        assertEquals(setOf("two.example.com"), result.blocked)
        assertEquals(2, result.version)
    }

    @Test
    fun `seeded entries are stored normalised`() {
        val releases = listOf(SeededRules.Release(blocked = listOf("  Ads.Example.COM. ")))
        val result = SeededRules.apply(emptySet(), emptySet(), 0, releases)
        assertEquals(setOf("ads.example.com"), result.blocked)
    }

    @Test
    fun `the seeded allow lets PayPal's bot check past a list that blocks it`() {
        // ShadowWhisperer's tracking list blocks both hosts. With them allowed, the engine
        // must answer them, since the user's allowed list is checked before any list.
        val shadowWhisperer = Blocklist(
            id = "tracking_shadowwhisperer",
            title = "ShadowWhisperer tracking list",
            blocked = DomainHashSet.build(listOf("bm.paypal.com", "perfdrive.com")),
        )
        val seeded = SeededRules.apply(emptySet(), emptySet(), 0)
        val engine = RuleEngine(
            RuleSet(blockedDomains = seeded.blocked, allowedDomains = seeded.allowed),
        ).apply { blocklists = BlocklistIndex(listOf(shadowWhisperer)) }

        assertEquals(Verdict.ALLOW, engine.decideHostname("bm.paypal.com").verdict)
        assertEquals(Verdict.ALLOW, engine.decideHostname("validate.perfdrive.com").verdict)
        // The rest of perfdrive.com stays blocked; only the challenge host is let through.
        assertEquals(Verdict.BLOCK, engine.decideHostname("collect.perfdrive.com").verdict)
    }

    @Test
    fun `the seeded blocks stop Yahoo Mail's inbox ads without touching mail`() {
        val seeded = SeededRules.apply(emptySet(), emptySet(), 0)
        val engine = RuleEngine(RuleSet(blockedDomains = seeded.blocked, allowedDomains = seeded.allowed))

        assertEquals(BlockReason.DOMAIN_BLOCKLIST, engine.decideHostname("gam.mail.yahoosandbox.net").reason)
        assertEquals(Verdict.BLOCK, engine.decideHostname("pbs.yahoo.com").verdict)
        assertEquals(Verdict.BLOCK, engine.decideHostname("pbd.yahoo.com").verdict)
        assertEquals(Verdict.ALLOW, engine.decideHostname("mail.yahoo.com").verdict)
        assertEquals(Verdict.ALLOW, engine.decideHostname("api.login.yahoo.com").verdict)
        // Only the ad host was seeded, not the whole sandbox domain.
        assertEquals(Verdict.ALLOW, engine.decideHostname("other.yahoosandbox.net").verdict)
    }
}
