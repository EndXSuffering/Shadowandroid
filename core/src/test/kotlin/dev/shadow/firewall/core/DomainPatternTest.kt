package dev.shadow.firewall.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DomainPatternTest {

    private fun pattern(rule: String) = DomainPattern.compile(rule)

    @Test
    fun `matches a rotating pool inside the first label`() {
        // Yahoo spreads its ad servers across ads-01, ads-02 and so on behind one rule. With
        // the wildcard dropped, whichever host a page picked simply was not blocked.
        val subject = assertNotNull(pattern("ads-*.v.ssp.yahoo.com"))
        assertTrue(subject.matches("ads-01.v.ssp.yahoo.com"))
        assertTrue(subject.matches("ads-17.v.ssp.yahoo.com"))
        assertTrue(subject.matches("ads-anything.v.ssp.yahoo.com"))
        assertFalse(subject.matches("v.ssp.yahoo.com"))
        assertFalse(subject.matches("www.yahoo.com"))
        assertFalse(subject.matches("ads-01.v.ssp.yahoo.com.evil.test"))
    }

    @Test
    fun `covers subdomains of a match like a plain rule does`() {
        val subject = assertNotNull(pattern("ads-*.v.ssp.yahoo.com"))
        assertTrue(subject.matches("eu.ads-01.v.ssp.yahoo.com"))
    }

    @Test
    fun `matches a wildcard in the middle and at the end`() {
        assertTrue(assertNotNull(pattern("adserver.*.yahoodns.net")).matches("adserver.eu.yahoodns.net"))
        assertTrue(assertNotNull(pattern("adservice.google.*")).matches("adservice.google.co.uk"))
        assertTrue(assertNotNull(pattern("putrr*.com")).matches("putrr18.com"))
    }

    @Test
    fun `refuses a pattern too thin to be safe`() {
        // These would each take out a slice of the internet, so they are dropped exactly as
        // they were before patterns were supported at all.
        assertNull(pattern("*"))
        assertNull(pattern("*.com"))
        assertNull(pattern("*ads*"))
        assertNull(pattern("*.co"))
    }

    @Test
    fun `refuses anything that is not a bare hostname pattern`() {
        assertNull(pattern("example.com/ads/*"))
        assertNull(pattern("http*://example.com"))
        assertNull(pattern("example.com no wildcard"))
        assertNull(pattern("plain.example.com"))
    }

    @Test
    fun `a dot in the pattern is literal, not a regex wildcard`() {
        val subject = assertNotNull(pattern("ads-*.v.ssp.yahoo.com"))
        assertFalse(subject.matches("ads-01xvxsspxyahooxcom"))
    }

    @Test
    fun `a set answers which pattern matched`() {
        val set = DomainPatternSet.build(
            listOf("ads-*.v.ssp.yahoo.com", "adservice.google.*", "*", "*.com"),
        )
        assertEquals(2, set.size) // the two unsafe ones are refused
        assertEquals("ads-*.v.ssp.yahoo.com", set.match("ads-03.v.ssp.yahoo.com")?.source)
        assertNull(set.match("news.yahoo.com"))
    }

    @Test
    fun `an empty set matches nothing`() {
        assertTrue(DomainPatternSet.EMPTY.isEmpty)
        assertFalse(DomainPatternSet.EMPTY.contains("anything.example.com"))
    }

    @Test
    fun `a list consults its patterns only after its exact entries miss`() {
        val list = Blocklist(
            id = "ads",
            title = "Ads",
            blocked = DomainHashSet.build(listOf("ads.yahoo.com")),
            blockedPatterns = DomainPatternSet.build(listOf("ads-*.v.ssp.yahoo.com")),
        )
        assertTrue(list.blocks("ads.yahoo.com"))
        assertTrue(list.blocks("ads-01.v.ssp.yahoo.com"))
        assertFalse(list.blocks("news.yahoo.com"))
    }

    @Test
    fun `a wildcard exception overrides a wildcard block`() {
        val list = Blocklist(
            id = "ads",
            title = "Ads",
            blocked = DomainHashSet.EMPTY,
            blockedPatterns = DomainPatternSet.build(listOf("ads-*.v.ssp.yahoo.com")),
            allowedPatterns = DomainPatternSet.build(listOf("ads-keepme*.v.ssp.yahoo.com")),
        )
        assertTrue(list.blocks("ads-01.v.ssp.yahoo.com"))
        assertFalse(list.blocks("ads-keepme9.v.ssp.yahoo.com"))
    }

    @Test
    fun `a subscribed allowlist pattern exempts across every list`() {
        val trackers = Blocklist(
            id = "trackers",
            title = "Trackers",
            blocked = DomainHashSet.build(listOf("go.redirectingat.com")),
        )
        val referrals = Blocklist(
            id = "referrals",
            title = "Referral allowlist",
            blocked = DomainHashSet.EMPTY,
            isAllowlist = true,
            allowedPatterns = DomainPatternSet.build(listOf("go.redirectingat.*")),
        )
        assertNull(BlocklistIndex(listOf(trackers, referrals)).match("go.redirectingat.com"))
        assertNotNull(BlocklistIndex(listOf(trackers)).match("go.redirectingat.com"))
    }

    @Test
    fun `patterns survive a round trip through the cache format`() {
        val original = DomainPatternSet.build(listOf("ads-*.v.ssp.yahoo.com", "adservice.google.*"))
        val bytes = java.io.ByteArrayOutputStream().also { original.writeTo(it) }.toByteArray()
        val restored = DomainPatternSet.readFrom(java.io.ByteArrayInputStream(bytes))
        assertEquals(original.size, restored.size)
        assertTrue(restored.contains("ads-05.v.ssp.yahoo.com"))
    }

    @Test
    fun `the parser hands a wildcard back as a pattern rule`() {
        val rule = assertNotNull(BlocklistParser.parseLine("||ads-*.v.ssp.yahoo.com^"))
        assertEquals(BlocklistParser.Kind.PATTERN, rule.kind)
        assertEquals(listOf("ads-*.v.ssp.yahoo.com"), rule.values)
        assertFalse(rule.isException)

        val exception = assertNotNull(BlocklistParser.parseLine("@@||ads-*.v.ssp.yahoo.com^"))
        assertEquals(BlocklistParser.Kind.PATTERN, exception.kind)
        assertTrue(exception.isException)
    }

    @Test
    fun `parsing a file sorts patterns away from plain domains`() {
        val parsed = BlocklistParser.parse(
            sequenceOf(
                "||ads.yahoo.com^",
                "||ads-*.v.ssp.yahoo.com^",
                "@@||keep-*.example.com^",
                "||example.com/ads/*",
            ),
        )
        assertEquals(listOf("ads.yahoo.com"), parsed.blocked)
        assertEquals(listOf("ads-*.v.ssp.yahoo.com"), parsed.blockedPatterns)
        assertEquals(listOf("keep-*.example.com"), parsed.allowedPatterns)
        assertEquals(1, parsed.skipped) // the path rule, still dropped
    }
}
