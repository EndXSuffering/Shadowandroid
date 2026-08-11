package dev.shadow.firewall.core

import java.net.Inet4Address
import java.net.InetAddress

/**
 * The 16-bit one's-complement checksum shared by IPv4, TCP and UDP (RFC 1071).
 *
 * Sums are carried as plain [Int]s. A 1500-byte packet contributes at most ~49M, so the
 * accumulator cannot overflow before it is folded.
 */
object Checksums {

    /** Accumulates [length] bytes starting at [offset] into [initial]; result is already folded. */
    fun sum(data: ByteArray, offset: Int, length: Int, initial: Int = 0): Int {
        var acc = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            acc += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            // Odd trailing byte is padded on the right with a zero byte.
            acc += (data[i].toInt() and 0xFF) shl 8
        }
        return fold(acc)
    }

    fun fold(value: Int): Int {
        var acc = value
        while ((acc ushr 16) != 0) acc = (acc and 0xFFFF) + (acc ushr 16)
        return acc
    }

    /** Turns an accumulated sum into the value that goes on the wire. */
    fun finish(accumulated: Int): Int {
        val folded = fold(accumulated)
        val checksum = folded.inv() and 0xFFFF
        // UDP uses 0 to mean "no checksum", so a computed 0 is transmitted as 0xFFFF.
        return checksum
    }

    /**
     * Sum of the TCP/UDP pseudo-header: the addresses, the protocol number and the length of
     * the transport segment.
     */
    fun pseudoHeaderSum(
        source: InetAddress,
        destination: InetAddress,
        protocol: Int,
        transportLength: Int,
    ): Int {
        val src = source.address
        val dst = destination.address
        var acc = sum(src, 0, src.size)
        acc = sum(dst, 0, dst.size, acc)
        return if (source is Inet4Address) {
            acc += protocol and 0xFF
            acc += transportLength and 0xFFFF
            fold(acc)
        } else {
            acc += (transportLength ushr 16) and 0xFFFF
            acc += transportLength and 0xFFFF
            acc += protocol and 0xFF
            fold(acc)
        }
    }
}
