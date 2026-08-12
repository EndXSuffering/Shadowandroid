package dev.shadow.firewall.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DomainHashSetTest {

    @Test
    fun `finds an exact domain`() {
        val set = DomainHashSet.build(listOf("doubleclick.net", "tracker.example.com"))
        assertTrue(set.containsExact("doubleclick.net"))
        assertTrue(set.containsExact("tracker.example.com"))
        assertFalse(set.containsExact("example.com"))
    }

    @Test
    fun `a parent domain covers its subdomains`() {
        val set = DomainHashSet.build(listOf("doubleclick.net"))
        assertTrue(set.contains("doubleclick.net"))
        assertTrue(set.contains("ad.doubleclick.net"))
        assertTrue(set.contains("a.b.c.doubleclick.net"))
    }

    @Test
    fun `a lookalike suffix is not a match`() {
        val set = DomainHashSet.build(listOf("example.com"))
        assertFalse(set.contains("notexample.com"))
        assertFalse(set.contains("example.com.evil.net"))
    }

    @Test
    fun `lookups ignore case and a trailing root dot`() {
        val set = DomainHashSet.build(listOf("Ads.Example.COM"))
        assertTrue(set.contains("ads.example.com"))
        assertTrue(set.contains("ADS.EXAMPLE.COM."))
        assertTrue(set.contains("sub.Ads.Example.com"))
    }

    @Test
    fun `duplicates collapse`() {
        val set = DomainHashSet.build(listOf("a.com", "a.com", "A.COM", "b.com"))
        assertEquals(2, set.size)
    }

    @Test
    fun `an empty set matches nothing`() {
        assertTrue(DomainHashSet.EMPTY.isEmpty)
        assertFalse(DomainHashSet.EMPTY.contains("anything.example.com"))
        assertEquals(0, DomainHashSet.build(emptyList()).size)
    }

    @Test
    fun `blank entries are dropped`() {
        assertEquals(1, DomainHashSet.build(listOf("", "   ", "a.com")).size)
    }

    @Test
    fun `survives a write and read round trip`() {
        val domains = (1..5000).map { "host$it.example.com" }
        val original = DomainHashSet.build(domains)

        val bytes = ByteArrayOutputStream().also { original.writeTo(it) }.toByteArray()
        val restored = DomainHashSet.readFrom(ByteArrayInputStream(bytes))

        assertEquals(original.size, restored.size)
        for (domain in domains) assertTrue(restored.containsExact(domain), domain)
        assertFalse(restored.containsExact("absent.example.com"))
    }

    @Test
    fun `the on-disk form is eight bytes per entry plus a short header`() {
        val set = DomainHashSet.build((1..1000).map { "host$it.example.com" })
        val bytes = ByteArrayOutputStream().also { set.writeTo(it) }.toByteArray()
        assertEquals(12 + 1000 * 8, bytes.size)
    }

    @Test
    fun `rejects a file that is not an index`() {
        val junk = ByteArrayInputStream(ByteArray(64) { 0x7 })
        assertFailsWith<IOException> { DomainHashSet.readFrom(junk) }
    }

    @Test
    fun `rejects an index whose entries are out of order`() {
        // Binary search on unsorted data returns wrong answers silently, so a corrupt file
        // has to fail loudly instead.
        val out = ByteArrayOutputStream()
        java.io.DataOutputStream(out).apply {
            writeInt(0x5346424C)
            writeInt(1)
            writeInt(3)
            writeLong(100); writeLong(50); writeLong(200)
        }
        assertFailsWith<IOException> { DomainHashSet.readFrom(ByteArrayInputStream(out.toByteArray())) }
    }

    @Test
    fun `rejects a header claiming an absurd entry count`() {
        val out = ByteArrayOutputStream()
        java.io.DataOutputStream(out).apply {
            writeInt(0x5346424C)
            writeInt(1)
            writeInt(Int.MAX_VALUE)
        }
        assertFailsWith<IOException> { DomainHashSet.readFrom(ByteArrayInputStream(out.toByteArray())) }
    }

    @Test
    fun `hashing is stable across calls`() {
        assertEquals(DomainHashSet.hash("example.com"), DomainHashSet.hash("example.com"))
        assertTrue(DomainHashSet.hash("example.com") != DomainHashSet.hash("example.net"))
    }

    @Test
    fun `a large realistic list has no internal hash collisions`() {
        // Two hundred thousand synthetic domains, the scale of a real ad list. If 64-bit
        // hashing were collision-prone at this size the deduplicated count would come up
        // short, and every collision is a domain silently blocked by mistake.
        val domains = buildList {
            for (i in 0 until 200_000) add("host-$i.list${i % 97}.example")
        }
        val set = DomainHashSet.build(domains)
        assertEquals(domains.size, set.size)
    }

    @Test
    fun `lookups stay fast on a large list`() {
        val set = DomainHashSet.build((0 until 200_000).map { "host-$it.example.com" })
        // Binary search over 200k entries is ~18 probes; a million lookups must not crawl.
        val start = System.nanoTime()
        var found = 0
        for (i in 0 until 100_000) {
            if (set.contains("sub.host-$i.example.com")) found++
        }
        val elapsedMillis = (System.nanoTime() - start) / 1_000_000
        assertEquals(100_000, found)
        assertTrue(elapsedMillis < 5_000, "100k lookups took ${elapsedMillis}ms")
    }
}
