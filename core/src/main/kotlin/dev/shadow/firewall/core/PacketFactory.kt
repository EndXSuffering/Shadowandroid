package dev.shadow.firewall.core

import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * Builds the IPv4/IPv6 packets we hand back to the app through the tun device.
 *
 * Everything the relay sends to an app — SYN/ACK, data, FIN, RST, DNS replies — comes from
 * here, so this is also the single place where checksums are computed.
 */
object PacketFactory {

    const val IPV4_HEADER = 20
    const val IPV6_HEADER = 40
    const val TCP_HEADER = 20
    const val UDP_HEADER = 8

    /** Largest TCP payload we will put on the wire for a given tunnel MTU. */
    fun maxSegmentSize(mtu: Int, ipv6: Boolean): Int =
        mtu - (if (ipv6) IPV6_HEADER else IPV4_HEADER) - TCP_HEADER

    private val identification = AtomicInteger(1)

    fun buildTcp(
        source: InetAddress,
        sourcePort: Int,
        destination: InetAddress,
        destinationPort: Int,
        sequenceNumber: Long,
        acknowledgementNumber: Long,
        flags: Int,
        window: Int,
        payload: ByteArray? = null,
        payloadOffset: Int = 0,
        payloadLength: Int = payload?.size ?: 0,
        mssOption: Int? = null,
    ): ByteArray {
        require(source.javaClass == destination.javaClass) { "address family mismatch" }
        val ipv6 = source !is Inet4Address
        val ipHeader = if (ipv6) IPV6_HEADER else IPV4_HEADER
        val optionsLength = if (mssOption != null) 4 else 0
        val tcpHeader = TCP_HEADER + optionsLength
        val transportLength = tcpHeader + payloadLength
        val out = ByteArray(ipHeader + transportLength)

        writeIpHeader(out, source, destination, IpProto.TCP, transportLength, ipv6)

        val t = ipHeader
        writeU16(out, t, sourcePort)
        writeU16(out, t + 2, destinationPort)
        writeU32(out, t + 4, sequenceNumber)
        writeU32(out, t + 8, acknowledgementNumber)
        out[t + 12] = ((tcpHeader / 4) shl 4).toByte()
        out[t + 13] = flags.toByte()
        writeU16(out, t + 14, window)
        // 16..17 checksum, filled in below. 18..19 urgent pointer stays zero.
        if (mssOption != null) {
            out[t + 20] = 2
            out[t + 21] = 4
            writeU16(out, t + 22, mssOption)
        }
        if (payload != null && payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, out, t + tcpHeader, payloadLength)
        }

        var acc = Checksums.pseudoHeaderSum(source, destination, IpProto.TCP, transportLength)
        acc = Checksums.sum(out, t, transportLength, acc)
        writeU16(out, t + 16, Checksums.finish(acc))
        return out
    }

    fun buildUdp(
        source: InetAddress,
        sourcePort: Int,
        destination: InetAddress,
        destinationPort: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size,
    ): ByteArray {
        require(source.javaClass == destination.javaClass) { "address family mismatch" }
        val ipv6 = source !is Inet4Address
        val ipHeader = if (ipv6) IPV6_HEADER else IPV4_HEADER
        val transportLength = UDP_HEADER + payloadLength
        val out = ByteArray(ipHeader + transportLength)

        writeIpHeader(out, source, destination, IpProto.UDP, transportLength, ipv6)

        val t = ipHeader
        writeU16(out, t, sourcePort)
        writeU16(out, t + 2, destinationPort)
        writeU16(out, t + 4, transportLength)
        System.arraycopy(payload, payloadOffset, out, t + UDP_HEADER, payloadLength)

        var acc = Checksums.pseudoHeaderSum(source, destination, IpProto.UDP, transportLength)
        acc = Checksums.sum(out, t, transportLength, acc)
        val checksum = Checksums.finish(acc)
        // In UDP a zero checksum means "not computed", so it is sent as all-ones instead.
        writeU16(out, t + 6, if (checksum == 0) 0xFFFF else checksum)
        return out
    }

    /**
     * A reset aimed at the app that sent [segment], used to fail blocked connections fast
     * instead of letting them hang until the app's own timeout.
     */
    fun buildRstFor(segment: TcpSegment): ByteArray {
        val packet = segment.packet
        // A reset for a SYN acknowledges the SYN; otherwise it carries the peer's ack number.
        val sequenceNumber: Long
        val acknowledgementNumber: Long
        val flags: Int
        if (segment.isAck && !segment.isSyn) {
            sequenceNumber = segment.acknowledgementNumber
            acknowledgementNumber = 0
            flags = TcpFlags.RST
        } else {
            sequenceNumber = 0
            acknowledgementNumber = nextSequence(
                segment.sequenceNumber,
                segment.payloadLength + (if (segment.isSyn) 1 else 0) + (if (segment.isFin) 1 else 0),
            )
            flags = TcpFlags.RST or TcpFlags.ACK
        }
        return buildTcp(
            source = packet.destinationAddress,
            sourcePort = segment.destinationPort,
            destination = packet.sourceAddress,
            destinationPort = segment.sourcePort,
            sequenceNumber = sequenceNumber,
            acknowledgementNumber = acknowledgementNumber,
            flags = flags,
            window = 0,
        )
    }

    /** Advances a sequence number, wrapping the way the 32-bit sequence space does. */
    fun nextSequence(sequenceNumber: Long, delta: Int): Long =
        (sequenceNumber + delta) and 0xFFFFFFFFL

    private fun writeIpHeader(
        out: ByteArray,
        source: InetAddress,
        destination: InetAddress,
        protocol: Int,
        transportLength: Int,
        ipv6: Boolean,
    ) {
        val src = source.address
        val dst = destination.address
        if (ipv6) {
            out[0] = 0x60
            writeU16(out, 4, transportLength)
            out[6] = protocol.toByte()
            out[7] = 64 // hop limit
            System.arraycopy(src, 0, out, 8, 16)
            System.arraycopy(dst, 0, out, 24, 16)
        } else {
            out[0] = 0x45
            writeU16(out, 2, IPV4_HEADER + transportLength)
            writeU16(out, 4, identification.getAndIncrement() and 0xFFFF)
            writeU16(out, 6, 0x4000) // don't fragment
            out[8] = 64 // ttl
            out[9] = protocol.toByte()
            System.arraycopy(src, 0, out, 12, 4)
            System.arraycopy(dst, 0, out, 16, 4)
            writeU16(out, 10, Checksums.finish(Checksums.sum(out, 0, IPV4_HEADER)))
        }
    }

    private fun writeU16(out: ByteArray, offset: Int, value: Int) {
        out[offset] = ((value ushr 8) and 0xFF).toByte()
        out[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(out: ByteArray, offset: Int, value: Long) {
        out[offset] = ((value ushr 24) and 0xFF).toByte()
        out[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        out[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        out[offset + 3] = (value and 0xFF).toByte()
    }
}
