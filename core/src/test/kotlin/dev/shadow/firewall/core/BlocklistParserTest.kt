package dev.shadow.firewall.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BlocklistParserTest {

    private fun blocked(line: String): List<String>? =
        BlocklistParser.parseLine(line)?.takeIf { !it.isException }?.domains

    private fun allowed(line: String): List<String>? =
        BlocklistParser.parseLine(line)?.takeIf { it.isException }?.domains

    // ------------------------------------------------------------- hosts

    @Test
    fun `reads a hosts entry`() {
        assertEquals(listOf("ads.example.com"), blocked("0.0.0.0 ads.example.com"))
        assertEquals(listOf("ads.example.com"), blocked("127.0.0.1  ads.example.com"))
        assertEquals(listOf("ads.example.com"), blocked("0.0.0.0\tads.example.com"))
    }

    @Test
    fun `reads a hosts entry with several hostnames`() {
        assertEquals(
            listOf("a.example.com", "b.example.com"),
            blocked("0.0.0.0 a.example.com b.example.com"),
        )
    }

    @Test
    fun `strips a trailing comment from a hosts entry`() {
        assertEquals(listOf("ads.example.com"), blocked("0.0.0.0 ads.example.com # tracker"))
    }

    @Test
    fun `skips the loopback boilerplate at the top of every hosts file`() {
        for (line in listOf(
            "127.0.0.1 localhost",
            "127.0.0.1 localhost.localdomain",
            "255.255.255.255 broadcasthost",
            "::1 ip6-localhost",
            "fe00::0 ip6-localnet",
        )) {
            assertNull(BlocklistParser.parseLine(line), line)
        }
    }

    // ----------------------------------------------------------- adblock

    @Test
    fun `reads an adguard domain rule`() {
        assertEquals(listOf("go.mobisla.com"), blocked("||go.mobisla.com^"))
        assertEquals(listOf("example.com"), blocked("||example.com^|"))
        assertEquals(listOf("example.com"), blocked("||example.com"))
    }

    @Test
    fun `reads an adguard exception as an allow`() {
        assertEquals(listOf("ad.abchina.com"), allowed("@@||ad.abchina.com^"))
    }

    @Test
    fun `keeps a rule whose only modifier is harmless`() {
        assertEquals(listOf("example.com"), blocked("||example.com^\$important"))
    }

    @Test
    fun `drops a rule with a modifier that narrows it`() {
        // $denyallow and $client mean "block except for…", which a plain domain block would
        // get wrong in the over-blocking direction.
        assertNull(BlocklistParser.parseLine("||example.com^\$denyallow=cdn.example.com"))
        assertNull(BlocklistParser.parseLine("||example.com^\$client=192.168.1.1"))
        assertNull(BlocklistParser.parseLine("||example.com^\$dnstype=AAAA"))
    }

    @Test
    fun `drops a path rule rather than blocking the whole host`() {
        assertNull(BlocklistParser.parseLine("||example.com/ads/banner.png"))
        assertNull(BlocklistParser.parseLine("||example.com/ads/*"))
    }

    @Test
    fun `keeps a rule with a trailing slash and nothing after it`() {
        assertEquals(listOf("example.com"), blocked("||example.com/"))
    }

    @Test
    fun `drops regex, cosmetic and wildcard rules`() {
        assertNull(BlocklistParser.parseLine("/banner\\d+\\.gif/"))
        assertNull(BlocklistParser.parseLine("@@/\\.(gif|jpe?g)#(\\/?.+)?/"))
        assertNull(BlocklistParser.parseLine("example.com##.ad-banner"))
        assertNull(BlocklistParser.parseLine("||*.doubleclick.net^"))
    }

    @Test
    fun `strips a scheme and a port`() {
        assertEquals(listOf("example.com"), blocked("||https://example.com^"))
        assertEquals(listOf("example.com"), blocked("||example.com:8080^"))
    }

    // ------------------------------------------------------------- plain

    @Test
    fun `reads a bare domain`() {
        assertEquals(listOf("00000.uno"), blocked("00000.uno"))
        assertEquals(listOf("sub.domain.example"), blocked("  sub.domain.example  "))
    }

    @Test
    fun `ignores comments and blank lines`() {
        assertNull(BlocklistParser.parseLine(""))
        assertNull(BlocklistParser.parseLine("   "))
        assertNull(BlocklistParser.parseLine("# This is a hosts comment"))
        assertNull(BlocklistParser.parseLine("! Title: AdGuard DNS filter"))
    }

    // -------------------------------------------------------- validation

    @Test
    fun `rejects entries that are not usable hostnames`() {
        for (candidate in listOf(
            "localhost", "com", "a..b.com", "-", "..", "1.2.3.4", "::1",
            "exam ple.com", "exam ple.com", "a".repeat(300) + ".com",
        )) {
            assertFalse(BlocklistParser.isValidDomain(candidate), candidate)
        }
    }

    @Test
    fun `accepts ordinary and punycode hostnames`() {
        for (candidate in listOf(
            "example.com", "a.b.c.example.co.uk", "xn--80ak6aa92e.com",
            "my_service.example.com", "1-2-3.example.com",
        )) {
            assertTrue(BlocklistParser.isValidDomain(candidate), candidate)
        }
    }

    @Test
    fun `a hosts line pointing at a literal address yields nothing to block`() {
        assertNull(BlocklistParser.parseLine("0.0.0.0 1.2.3.4"))
    }

    // ---------------------------------------------------------- addresses

    @Test
    fun `an adblock rule naming a literal address becomes an address rule`() {
        val rule = assertNotNull(BlocklistParser.parseLine("||109.201.135.46^"))
        assertEquals(BlocklistParser.Kind.ADDRESS, rule.kind)
        assertEquals(listOf("109.201.135.46"), rule.values)
        assertTrue(rule.domains.isEmpty(), "an address is not a domain")
    }

    @Test
    fun `an ipv6 address rule is canonicalised to the form the tunnel reports`() {
        val rule = assertNotNull(BlocklistParser.parseLine("||[2001:db8::1]^"))
        assertEquals(BlocklistParser.Kind.ADDRESS, rule.kind)
        assertEquals(listOf("2001:db8:0:0:0:0:0:1"), rule.values)
    }

    @Test
    fun `a port is stripped from a host but never from an ipv6 literal`() {
        assertEquals(listOf("example.com"), blocked("||example.com:8080^"))
        val v6 = assertNotNull(BlocklistParser.parseLine("||2001:db8::1^"))
        assertEquals(listOf("2001:db8:0:0:0:0:0:1"), v6.values)
    }

    @Test
    fun `address rules are collected separately when parsing a file`() {
        val parsed = BlocklistParser.parse(
            sequenceOf("||ads.example.com^", "||109.201.135.46^", "||malware.example.net^"),
        )
        assertEquals(listOf("ads.example.com", "malware.example.net"), parsed.blocked)
        assertEquals(listOf("109.201.135.46"), parsed.blockedAddresses)
    }

    @Test
    fun `lowercases and trims the root dot`() {
        assertEquals(listOf("ads.example.com"), blocked("0.0.0.0 ADS.Example.COM."))
    }

    // --------------------------------------------------------- whole file

    @Test
    fun `parses a mixed file and separates exceptions`() {
        val text = """
            ! Title: Test list
            # a hosts comment
            0.0.0.0 tracker.example.com
            ||ads.example.net^
            @@||allowed.example.net^
            plain.example.org
            ||withpath.example.com/ads/
        """.trimIndent().lineSequence()

        val parsed = BlocklistParser.parse(text)
        assertEquals(
            listOf("tracker.example.com", "ads.example.net", "plain.example.org"),
            parsed.blocked,
        )
        assertEquals(listOf("allowed.example.net"), parsed.allowed)
        assertTrue(parsed.blockedAddresses.isEmpty())
        assertEquals(1, parsed.skipped, "the path rule should count as skipped")
    }

    @Test
    fun `a parsed list feeds straight into a lookup index`() {
        val parsed = BlocklistParser.parse(
            sequenceOf("||doubleclick.net^", "0.0.0.0 tracker.example.com", "@@||safe.doubleclick.net^"),
        )
        val list = Blocklist(
            id = "test",
            title = "Test list",
            blocked = DomainHashSet.build(parsed.blocked),
            allowed = DomainHashSet.build(parsed.allowed),
        )

        assertTrue(list.blocks("doubleclick.net"))
        assertTrue(list.blocks("ad.doubleclick.net"), "subdomains inherit the block")
        assertTrue(list.blocks("tracker.example.com"))
        assertFalse(list.blocks("safe.doubleclick.net"), "the list's own exception wins")
        assertFalse(list.blocks("example.com"))

        val index = BlocklistIndex(listOf(list))
        assertEquals("Test list", assertNotNull(index.match("ad.doubleclick.net")).title)
        assertNull(index.match("unrelated.example"))
    }
}
