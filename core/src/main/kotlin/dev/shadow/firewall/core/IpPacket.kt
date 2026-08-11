package dev.shadow.firewall.core

import java.net.InetAddress

/**
 * A read-only view over one IPv4 or IPv6 datagram that is already sitting in [data].
 *
 * Nothing is copied: [payloadOffset] and [payloadLength] point back into the caller's buffer,
 * which lets the tunnel loop reuse a single read buffer for every packet.
 */
class IpPacket private constructor(
    val data: ByteArray,
    val offset: Int,
    val length: Int,
    val version: Int,
    val protocol: Int,
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val payloadOffset: Int,
    val payloadLength: Int,
    /** True for a fragment we are not able to reassemble; callers should drop these. */
    val fragmented: Boolean,
) {
    val isIpv6: Boolean get() = version == 6

    fun tcp(): TcpSegment? =
        if (protocol == IpProto.TCP) TcpSegment.parse(this) else null

    fun udp(): UdpDatagram? =
        if (protocol == IpProto.UDP) UdpDatagram.parse(this) else null

    companion object {
        private const val IPV4_MIN_HEADER = 20
        private const val IPV6_HEADER = 40

        fun parse(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): IpPacket? {
            if (length < IPV4_MIN_HEADER) return null
            return when ((data[offset].toInt() ushr 4) and 0x0F) {
                4 -> parseV4(data, offset, length)
                6 -> parseV6(data, offset, length)
                else -> null
            }
        }

        private fun parseV4(data: ByteArray, offset: Int, length: Int): IpPacket? {
            val headerLength = (data[offset].toInt() and 0x0F) * 4
            if (headerLength < IPV4_MIN_HEADER || headerLength > length) return null

            val totalLength = u16(data, offset + 2)
            // Some stacks pad the frame; trust the smaller of the two lengths.
            val effective = if (totalLength in headerLength..length) totalLength else length
            val protocol = data[offset + 9].toInt() and 0xFF

            val flagsAndFragment = u16(data, offset + 6)
            val moreFragments = (flagsAndFragment and 0x2000) != 0
            val fragmentOffset = flagsAndFragment and 0x1FFF

            return IpPacket(
                data = data,
                offset = offset,
                length = effective,
                version = 4,
                protocol = protocol,
                sourceAddress = address(data, offset + 12, 4),
                destinationAddress = address(data, offset + 16, 4),
                payloadOffset = offset + headerLength,
                payloadLength = effective - headerLength,
                fragmented = moreFragments || fragmentOffset != 0,
            )
        }

        private fun parseV6(data: ByteArray, offset: Int, length: Int): IpPacket? {
            if (length < IPV6_HEADER) return null
            val payloadLength = u16(data, offset + 4)
            val effective = if (IPV6_HEADER + payloadLength <= length) IPV6_HEADER + payloadLength else length

            var nextHeader = data[offset + 6].toInt() and 0xFF
            var cursor = offset + IPV6_HEADER
            var fragmented = false

            // Walk the extension-header chain to find the real transport header.
            while (cursor + 2 <= offset + effective) {
                when (nextHeader) {
                    0, 43, 60 -> { // hop-by-hop, routing, destination options
                        val extLength = ((data[cursor + 1].toInt() and 0xFF) + 1) * 8
                        nextHeader = data[cursor].toInt() and 0xFF
                        cursor += extLength
                    }
                    44 -> { // fragment header: we do not reassemble
                        fragmented = true
                        nextHeader = data[cursor].toInt() and 0xFF
                        cursor += 8
                    }
                    else -> break
                }
            }
            if (cursor > offset + effective) return null

            return IpPacket(
                data = data,
                offset = offset,
                length = effective,
                version = 6,
                protocol = nextHeader,
                sourceAddress = address(data, offset + 8, 16),
                destinationAddress = address(data, offset + 24, 16),
                payloadOffset = cursor,
                payloadLength = offset + effective - cursor,
                fragmented = fragmented,
            )
        }

        private fun address(data: ByteArray, offset: Int, size: Int): InetAddress =
            InetAddress.getByAddress(data.copyOfRange(offset, offset + size))

        internal fun u16(data: ByteArray, offset: Int): Int =
            ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

        internal fun u32(data: ByteArray, offset: Int): Long =
            ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
    }
}

/** TCP flag bits, in the order they sit in the header. */
object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
    const val URG = 0x20

    fun describe(flags: Int): String = buildString {
        if (flags and SYN != 0) append("SYN ")
        if (flags and ACK != 0) append("ACK ")
        if (flags and PSH != 0) append("PSH ")
        if (flags and FIN != 0) append("FIN ")
        if (flags and RST != 0) append("RST ")
    }.trim()
}

class TcpSegment private constructor(
    val packet: IpPacket,
    val sourcePort: Int,
    val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgementNumber: Long,
    val flags: Int,
    val window: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    /** MSS advertised by the peer, when the option is present. */
    val maxSegmentSize: Int?,
) {
    val isSyn: Boolean get() = flags and TcpFlags.SYN != 0
    val isAck: Boolean get() = flags and TcpFlags.ACK != 0
    val isFin: Boolean get() = flags and TcpFlags.FIN != 0
    val isRst: Boolean get() = flags and TcpFlags.RST != 0

    fun payload(): ByteArray =
        packet.data.copyOfRange(payloadOffset, payloadOffset + payloadLength)

    companion object {
        fun parse(packet: IpPacket): TcpSegment? {
            val data = packet.data
            val base = packet.payloadOffset
            if (packet.payloadLength < 20) return null

            val dataOffset = ((data[base + 12].toInt() and 0xF0) ushr 4) * 4
            if (dataOffset < 20 || dataOffset > packet.payloadLength) return null

            return TcpSegment(
                packet = packet,
                sourcePort = IpPacket.u16(data, base),
                destinationPort = IpPacket.u16(data, base + 2),
                sequenceNumber = IpPacket.u32(data, base + 4),
                acknowledgementNumber = IpPacket.u32(data, base + 8),
                flags = data[base + 13].toInt() and 0x3F,
                window = IpPacket.u16(data, base + 14),
                payloadOffset = base + dataOffset,
                payloadLength = packet.payloadLength - dataOffset,
                maxSegmentSize = readMss(data, base + 20, base + dataOffset),
            )
        }

        private fun readMss(data: ByteArray, start: Int, end: Int): Int? {
            var i = start
            while (i < end) {
                when (data[i].toInt() and 0xFF) {
                    0 -> return null // end of option list
                    1 -> i++ // no-op padding
                    2 -> {
                        if (i + 4 > end) return null
                        return IpPacket.u16(data, i + 2)
                    }
                    else -> {
                        if (i + 1 >= end) return null
                        val optionLength = data[i + 1].toInt() and 0xFF
                        if (optionLength < 2) return null
                        i += optionLength
                    }
                }
            }
            return null
        }
    }
}

class UdpDatagram private constructor(
    val packet: IpPacket,
    val sourcePort: Int,
    val destinationPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) {
    fun payload(): ByteArray =
        packet.data.copyOfRange(payloadOffset, payloadOffset + payloadLength)

    companion object {
        fun parse(packet: IpPacket): UdpDatagram? {
            val data = packet.data
            val base = packet.payloadOffset
            if (packet.payloadLength < 8) return null

            val declared = IpPacket.u16(data, base + 4)
            val available = packet.payloadLength - 8
            val payloadLength = if (declared in 8..packet.payloadLength) declared - 8 else available

            return UdpDatagram(
                packet = packet,
                sourcePort = IpPacket.u16(data, base),
                destinationPort = IpPacket.u16(data, base + 2),
                payloadOffset = base + 8,
                payloadLength = payloadLength,
            )
        }
    }
}
