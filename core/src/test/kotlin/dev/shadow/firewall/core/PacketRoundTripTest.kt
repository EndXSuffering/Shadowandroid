package dev.shadow.firewall.core

import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PacketRoundTripTest {

    private val v4Client = InetAddress.getByName("10.111.222.1")
    private val v4Server = InetAddress.getByName("93.184.216.34")
    private val v6Client = InetAddress.getByName("fd00:1:2:3::1")
    private val v6Server = InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946")

    @Test
    fun `ipv4 tcp packet survives a build and parse round trip`() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val bytes = PacketFactory.buildTcp(
            source = v4Server,
            sourcePort = 443,
            destination = v4Client,
            destinationPort = 51234,
            sequenceNumber = 0x11223344,
            acknowledgementNumber = 0x55667788,
            flags = TcpFlags.PSH or TcpFlags.ACK,
            window = 65535,
            payload = payload,
        )

        val packet = assertNotNull(IpPacket.parse(bytes))
        assertEquals(4, packet.version)
        assertEquals(IpProto.TCP, packet.protocol)
        assertEquals(v4Server, packet.sourceAddress)
        assertEquals(v4Client, packet.destinationAddress)
        assertEquals(bytes.size, packet.length)

        val tcp = assertNotNull(packet.tcp())
        assertEquals(443, tcp.sourcePort)
        assertEquals(51234, tcp.destinationPort)
        assertEquals(0x11223344L, tcp.sequenceNumber)
        assertEquals(0x55667788L, tcp.acknowledgementNumber)
        assertEquals(65535, tcp.window)
        assertTrue(tcp.isAck)
        assertTrue(!tcp.isSyn)
        assertContentEquals(payload, tcp.payload())
    }

    @Test
    fun `ipv6 tcp packet survives a build and parse round trip`() {
        val bytes = PacketFactory.buildTcp(
            source = v6Server,
            sourcePort = 80,
            destination = v6Client,
            destinationPort = 40000,
            sequenceNumber = 1,
            acknowledgementNumber = 2,
            flags = TcpFlags.SYN or TcpFlags.ACK,
            window = 32768,
            mssOption = 1440,
        )

        val packet = assertNotNull(IpPacket.parse(bytes))
        assertEquals(6, packet.version)
        assertEquals(v6Server, packet.sourceAddress)
        assertEquals(v6Client, packet.destinationAddress)

        val tcp = assertNotNull(packet.tcp())
        assertTrue(tcp.isSyn && tcp.isAck)
        assertEquals(1440, tcp.maxSegmentSize)
        assertEquals(0, tcp.payloadLength)
    }

    @Test
    fun `udp packet survives a build and parse round trip`() {
        val payload = ByteArray(200) { (it and 0xFF).toByte() }
        val bytes = PacketFactory.buildUdp(
            source = v4Server,
            sourcePort = 53,
            destination = v4Client,
            destinationPort = 33445,
            payload = payload,
        )

        val packet = assertNotNull(IpPacket.parse(bytes))
        val udp = assertNotNull(packet.udp())
        assertEquals(53, udp.sourcePort)
        assertEquals(33445, udp.destinationPort)
        assertEquals(200, udp.payloadLength)
        assertContentEquals(payload, udp.payload())
    }

    @Test
    fun `checksums verify to zero over the built packet`() {
        // Summing a correct header including its checksum field yields all ones.
        val bytes = PacketFactory.buildTcp(
            source = v4Server, sourcePort = 443,
            destination = v4Client, destinationPort = 51234,
            sequenceNumber = 7, acknowledgementNumber = 9,
            flags = TcpFlags.ACK, window = 100,
            payload = byteArrayOf(1, 2, 3),
        )

        assertEquals(0xFFFF, Checksums.sum(bytes, 0, PacketFactory.IPV4_HEADER))

        val transportLength = bytes.size - PacketFactory.IPV4_HEADER
        val pseudo = Checksums.pseudoHeaderSum(v4Server, v4Client, IpProto.TCP, transportLength)
        assertEquals(
            0xFFFF,
            Checksums.sum(bytes, PacketFactory.IPV4_HEADER, transportLength, pseudo),
        )
    }

    @Test
    fun `ipv6 transport checksum verifies`() {
        val bytes = PacketFactory.buildUdp(
            source = v6Server, sourcePort = 53,
            destination = v6Client, destinationPort = 5353,
            payload = byteArrayOf(9, 8, 7, 6, 5),
        )
        val transportLength = bytes.size - PacketFactory.IPV6_HEADER
        val pseudo = Checksums.pseudoHeaderSum(v6Server, v6Client, IpProto.UDP, transportLength)
        assertEquals(
            0xFFFF,
            Checksums.sum(bytes, PacketFactory.IPV6_HEADER, transportLength, pseudo),
        )
    }

    @Test
    fun `odd length payload is checksummed with right hand zero padding`() {
        val bytes = PacketFactory.buildUdp(
            source = v4Server, sourcePort = 1,
            destination = v4Client, destinationPort = 2,
            payload = byteArrayOf(0x41), // single byte forces the odd-length branch
        )
        val transportLength = bytes.size - PacketFactory.IPV4_HEADER
        val pseudo = Checksums.pseudoHeaderSum(v4Server, v4Client, IpProto.UDP, transportLength)
        assertEquals(
            0xFFFF,
            Checksums.sum(bytes, PacketFactory.IPV4_HEADER, transportLength, pseudo),
        )
    }

    @Test
    fun `reset for a syn acknowledges the syn and reverses the direction`() {
        val syn = PacketFactory.buildTcp(
            source = v4Client, sourcePort = 51234,
            destination = v4Server, destinationPort = 443,
            sequenceNumber = 1000, acknowledgementNumber = 0,
            flags = TcpFlags.SYN, window = 65535, mssOption = 1460,
        )
        val segment = assertNotNull(assertNotNull(IpPacket.parse(syn)).tcp())

        val reset = assertNotNull(IpPacket.parse(PacketFactory.buildRstFor(segment)))
        assertEquals(v4Server, reset.sourceAddress)
        assertEquals(v4Client, reset.destinationAddress)

        val rst = assertNotNull(reset.tcp())
        assertEquals(443, rst.sourcePort)
        assertEquals(51234, rst.destinationPort)
        assertTrue(rst.isRst)
        // SYN occupies one sequence number, so the reset acknowledges 1001.
        assertEquals(1001L, rst.acknowledgementNumber)
    }

    @Test
    fun `reset for an established segment uses the peer ack as its sequence`() {
        val data = PacketFactory.buildTcp(
            source = v4Client, sourcePort = 51234,
            destination = v4Server, destinationPort = 443,
            sequenceNumber = 500, acknowledgementNumber = 9000,
            flags = TcpFlags.ACK or TcpFlags.PSH, window = 65535,
            payload = byteArrayOf(1, 2, 3, 4),
        )
        val segment = assertNotNull(assertNotNull(IpPacket.parse(data)).tcp())
        val rst = assertNotNull(assertNotNull(IpPacket.parse(PacketFactory.buildRstFor(segment))).tcp())

        assertTrue(rst.isRst)
        assertEquals(9000L, rst.sequenceNumber)
    }

    @Test
    fun `sequence numbers wrap at the 32 bit boundary`() {
        assertEquals(0L, PacketFactory.nextSequence(0xFFFFFFFFL, 1))
        assertEquals(4L, PacketFactory.nextSequence(0xFFFFFFFFL, 5))
        assertEquals(0xFFFFFFFFL, PacketFactory.nextSequence(0xFFFFFFFEL, 1))
    }

    @Test
    fun `high sequence numbers round trip without sign extension`() {
        val bytes = PacketFactory.buildTcp(
            source = v4Server, sourcePort = 443,
            destination = v4Client, destinationPort = 1,
            sequenceNumber = 0xFFFFFFFFL, acknowledgementNumber = 0x80000000L,
            flags = TcpFlags.ACK, window = 1,
        )
        val tcp = assertNotNull(assertNotNull(IpPacket.parse(bytes)).tcp())
        assertEquals(0xFFFFFFFFL, tcp.sequenceNumber)
        assertEquals(0x80000000L, tcp.acknowledgementNumber)
    }

    @Test
    fun `truncated and malformed buffers are rejected rather than throwing`() {
        assertNull(IpPacket.parse(ByteArray(0)))
        assertNull(IpPacket.parse(ByteArray(19)))
        // Version 7 is not a thing.
        assertNull(IpPacket.parse(ByteArray(40).also { it[0] = 0x70 }))
        // IHL of 0 is shorter than the minimum header.
        assertNull(IpPacket.parse(ByteArray(40).also { it[0] = 0x40 }))
    }

    @Test
    fun `tcp parse rejects a data offset that runs past the packet`() {
        val bytes = PacketFactory.buildTcp(
            source = v4Server, sourcePort = 1,
            destination = v4Client, destinationPort = 2,
            sequenceNumber = 0, acknowledgementNumber = 0,
            flags = TcpFlags.ACK, window = 0,
        )
        // Claim a 60-byte TCP header inside a 20-byte one.
        bytes[PacketFactory.IPV4_HEADER + 12] = 0xF0.toByte()
        assertNull(assertNotNull(IpPacket.parse(bytes)).tcp())
    }

    @Test
    fun `mss option is found after padding options`() {
        val bytes = PacketFactory.buildTcp(
            source = v4Client, sourcePort = 1,
            destination = v4Server, destinationPort = 2,
            sequenceNumber = 0, acknowledgementNumber = 0,
            flags = TcpFlags.SYN, window = 0, mssOption = 1300,
        )
        assertEquals(1300, assertNotNull(assertNotNull(IpPacket.parse(bytes)).tcp()).maxSegmentSize)
    }

    @Test
    fun `max segment size leaves room for the ip and tcp headers`() {
        assertEquals(1460, PacketFactory.maxSegmentSize(1500, ipv6 = false))
        assertEquals(1440, PacketFactory.maxSegmentSize(1500, ipv6 = true))
    }
}
