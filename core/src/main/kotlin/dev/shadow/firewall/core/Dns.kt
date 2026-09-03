package dev.shadow.firewall.core

import java.net.InetAddress

/**
 * Just enough DNS to do two jobs: learn which hostname an IP belongs to (so the traffic log
 * shows names instead of bare addresses), and answer blocked lookups with NXDOMAIN.
 *
 * This is a parser for untrusted bytes, so every read is bounds-checked and name decoding has
 * a hard cap on pointer hops.
 */
object Dns {

    /** The well-known port, where cleartext lookups can still be inspected. */
    const val PORT = 53

    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28

    const val RCODE_NO_ERROR = 0
    const val RCODE_NAME_ERROR = 3

    private const val HEADER_LENGTH = 12
    private const val MAX_POINTER_HOPS = 64
    private const val MAX_NAME_LENGTH = 255

    data class Question(val name: String, val type: Int, val dnsClass: Int)

    data class Record(
        val name: String,
        val type: Int,
        val ttlSeconds: Long,
        val address: InetAddress?,
        val canonicalName: String?,
    )

    data class Message(
        val id: Int,
        val isResponse: Boolean,
        val responseCode: Int,
        val questions: List<Question>,
        val answers: List<Record>,
    ) {
        /** The name being looked up, which is all the blocklist needs. */
        val queryName: String? get() = questions.firstOrNull()?.name

        /** Every address this response hands back, for the IP to hostname map. */
        fun addresses(): List<InetAddress> = answers.mapNotNull { it.address }
    }

    fun parse(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Message? {
        if (length < HEADER_LENGTH) return null
        val end = offset + length

        val id = u16(data, offset) ?: return null
        val flags = u16(data, offset + 2) ?: return null
        val questionCount = u16(data, offset + 4) ?: return null
        val answerCount = u16(data, offset + 6) ?: return null

        // A malformed header can claim thousands of records; each one needs at least a byte.
        if (questionCount > length || answerCount > length) return null

        var cursor = offset + HEADER_LENGTH
        val questions = ArrayList<Question>(questionCount)
        repeat(questionCount) {
            val name = readName(data, cursor, offset, end) ?: return null
            cursor = name.second
            val type = u16(data, cursor) ?: return null
            val dnsClass = u16(data, cursor + 2) ?: return null
            cursor += 4
            if (cursor > end) return null
            questions += Question(name.first, type, dnsClass)
        }

        val answers = ArrayList<Record>(answerCount)
        repeat(answerCount) {
            val name = readName(data, cursor, offset, end) ?: return@repeat
            cursor = name.second
            val type = u16(data, cursor) ?: return@repeat
            val ttl = u32(data, cursor + 4) ?: return@repeat
            val dataLength = u16(data, cursor + 8) ?: return@repeat
            cursor += 10
            if (cursor + dataLength > end) return@repeat

            val address = when {
                type == TYPE_A && dataLength == 4 ->
                    InetAddress.getByAddress(data.copyOfRange(cursor, cursor + 4))
                type == TYPE_AAAA && dataLength == 16 ->
                    InetAddress.getByAddress(data.copyOfRange(cursor, cursor + 16))
                else -> null
            }
            val canonicalName =
                if (type == TYPE_CNAME) readName(data, cursor, offset, end)?.first else null

            answers += Record(name.first, type, ttl, address, canonicalName)
            cursor += dataLength
        }

        return Message(
            id = id,
            isResponse = (flags and 0x8000) != 0,
            responseCode = flags and 0x000F,
            questions = questions,
            answers = answers,
        )
    }

    /**
     * Builds an NXDOMAIN reply to [query], echoing its header id and question section so the
     * asking resolver accepts it. Returns null if the query is not something we can mirror.
     */
    fun buildNxDomain(query: ByteArray, offset: Int = 0, length: Int = query.size - offset): ByteArray? {
        if (length < HEADER_LENGTH) return null
        val end = offset + length
        val questionCount = u16(query, offset + 4) ?: return null
        if (questionCount < 1) return null

        // Find where the question section ends so we can copy it verbatim.
        var cursor = offset + HEADER_LENGTH
        repeat(questionCount) {
            val name = readName(query, cursor, offset, end) ?: return null
            cursor = name.second + 4
            if (cursor > end) return null
        }

        val size = cursor - offset
        val out = query.copyOfRange(offset, offset + size)
        val flags = u16(query, offset + 2) ?: return null
        // QR=1, keep OPCODE and RD, set RA=1, RCODE=NXDOMAIN.
        val responseFlags = 0x8000 or (flags and 0x7900) or 0x0080 or RCODE_NAME_ERROR
        out[2] = ((responseFlags ushr 8) and 0xFF).toByte()
        out[3] = (responseFlags and 0xFF).toByte()
        // No answer, authority or additional records.
        for (i in 6..11) out[i] = 0
        return out
    }

    /** Returns the decoded name and the offset just past the name in the wire format. */
    private fun readName(
        data: ByteArray,
        start: Int,
        messageStart: Int,
        end: Int,
    ): Pair<String, Int>? {
        val builder = StringBuilder()
        var cursor = start
        var afterName = -1
        var hops = 0

        while (cursor < end) {
            val lengthByte = data[cursor].toInt() and 0xFF
            when {
                lengthByte == 0 -> {
                    cursor++
                    return Pair(builder.toString(), if (afterName >= 0) afterName else cursor)
                }
                (lengthByte and 0xC0) == 0xC0 -> {
                    if (cursor + 1 >= end) return null
                    if (++hops > MAX_POINTER_HOPS) return null
                    val pointer = messageStart + (((lengthByte and 0x3F) shl 8) or (data[cursor + 1].toInt() and 0xFF))
                    if (pointer < messageStart || pointer >= end) return null
                    if (afterName < 0) afterName = cursor + 2
                    cursor = pointer
                }
                else -> {
                    if (cursor + 1 + lengthByte > end) return null
                    if (builder.length + lengthByte + 1 > MAX_NAME_LENGTH) return null
                    if (builder.isNotEmpty()) builder.append('.')
                    for (i in 0 until lengthByte) {
                        builder.append((data[cursor + 1 + i].toInt() and 0xFF).toChar())
                    }
                    cursor += 1 + lengthByte
                }
            }
        }
        return null
    }

    private fun u16(data: ByteArray, offset: Int): Int? {
        if (offset < 0 || offset + 2 > data.size) return null
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private fun u32(data: ByteArray, offset: Int): Long? {
        if (offset < 0 || offset + 4 > data.size) return null
        return ((data[offset].toLong() and 0xFF) shl 24) or
            ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or
            (data[offset + 3].toLong() and 0xFF)
    }
}
