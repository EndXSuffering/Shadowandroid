package dev.shadow.firewall.core

/**
 * The client half of SOCKS5 (RFC 1928) — just enough of it to ask a proxy running on the
 * device to open one outbound TCP connection on our behalf.
 *
 * No authentication is offered. The only proxy this talks to is a loopback listener belonging
 * to another app on the same phone, so there is no credential to present and nothing between
 * us and it that could read one.
 */
object Socks5 {

    const val VERSION = 5
    const val COMMAND_CONNECT = 1
    const val NO_AUTHENTICATION = 0
    const val NO_ACCEPTABLE_METHODS = 0xFF

    const val ADDRESS_IPV4 = 1
    const val ADDRESS_DOMAIN = 3
    const val ADDRESS_IPV6 = 4

    /** Version 5, one method offered, and that method is "no authentication". */
    val GREETING: ByteArray = byteArrayOf(VERSION.toByte(), 1, NO_AUTHENTICATION.toByte())

    /** A CONNECT request for a literal address, which must be 4 or 16 bytes. */
    fun connectRequest(address: ByteArray, port: Int): ByteArray {
        val type = when (address.size) {
            4 -> ADDRESS_IPV4
            16 -> ADDRESS_IPV6
            else -> throw IllegalArgumentException("address must be 4 or 16 bytes")
        }
        val out = ByteArray(6 + address.size)
        out[0] = VERSION.toByte()
        out[1] = COMMAND_CONNECT.toByte()
        out[2] = 0 // reserved
        out[3] = type.toByte()
        address.copyInto(out, 4)
        out[out.size - 2] = ((port ushr 8) and 0xFF).toByte()
        out[out.size - 1] = (port and 0xFF).toByte()
        return out
    }

    /** How long a reply carrying [addressType] is in total, or null if the type is unknown. */
    fun replyLength(addressType: Int, firstAddressByte: Int): Int? = when (addressType) {
        ADDRESS_IPV4 -> 4 + 4 + 2
        ADDRESS_IPV6 -> 4 + 16 + 2
        ADDRESS_DOMAIN -> 4 + 1 + firstAddressByte + 2
        else -> null
    }

    /** Plain-language form of a SOCKS reply code, for the log. */
    fun replyMessage(code: Int): String = when (code) {
        0 -> "succeeded"
        1 -> "proxy failure"
        2 -> "not allowed by the proxy"
        3 -> "network unreachable"
        4 -> "host unreachable"
        5 -> "connection refused"
        6 -> "TTL expired"
        7 -> "CONNECT not supported"
        8 -> "address type not supported"
        else -> "reply code $code"
    }
}

/**
 * Drives one SOCKS5 CONNECT to completion over a non-blocking socket.
 *
 * The socket hands us whatever bytes have arrived, in whatever sizes; this accumulates them
 * and only acts once a whole message is present. It is deliberately free of any I/O so the
 * protocol can be tested without a proxy to talk to.
 */
class Socks5Client(private val request: ByteArray) {

    sealed interface Step {
        /** Write these bytes to the proxy, then keep reading. */
        class Send(val bytes: ByteArray) : Step

        /** The message is incomplete; read more. */
        data object NeedMore : Step

        /**
         * The proxy has opened the connection. [earlyData] is anything the server had already
         * sent that arrived in the same read as the reply — rare, but losing it would corrupt
         * the very first bytes of the stream.
         */
        class Ready(val earlyData: ByteArray) : Step

        /** The handshake cannot complete; the caller should tear the connection down. */
        class Failed(val reason: String) : Step
    }

    private enum class Stage { METHOD, REPLY, DONE }

    private var stage = Stage.METHOD
    private var buffer = ByteArray(0)

    /** The first thing to write, before anything is read. */
    fun greeting(): ByteArray = Socks5.GREETING

    fun onBytes(data: ByteArray, offset: Int, length: Int): Step {
        if (stage == Stage.DONE) return Step.Failed("unexpected data after the handshake")
        buffer += data.copyOfRange(offset, offset + length)

        return when (stage) {
            Stage.METHOD -> onMethodSelection()
            Stage.REPLY -> onConnectReply()
            Stage.DONE -> Step.Failed("unexpected data after the handshake")
        }
    }

    private fun onMethodSelection(): Step {
        if (buffer.size < 2) return Step.NeedMore
        val version = buffer[0].toInt() and 0xFF
        val method = buffer[1].toInt() and 0xFF
        if (version != Socks5.VERSION) return Step.Failed("not a SOCKS5 proxy")
        if (method == Socks5.NO_ACCEPTABLE_METHODS) {
            return Step.Failed("the proxy requires authentication")
        }
        if (method != Socks5.NO_AUTHENTICATION) {
            return Step.Failed("unsupported authentication method $method")
        }

        // A well-behaved proxy sends nothing more until it has our request, but keep anything
        // that did arrive: it is the start of the reply, and the next read will parse it.
        buffer = buffer.copyOfRange(2, buffer.size)
        stage = Stage.REPLY
        return Step.Send(request)
    }

    private fun onConnectReply(): Step {
        if (buffer.size < 5) return Step.NeedMore
        if ((buffer[0].toInt() and 0xFF) != Socks5.VERSION) return Step.Failed("not a SOCKS5 proxy")

        val code = buffer[1].toInt() and 0xFF
        val addressType = buffer[3].toInt() and 0xFF
        val total = Socks5.replyLength(addressType, buffer[4].toInt() and 0xFF)
            ?: return Step.Failed("unknown address type $addressType in the reply")
        if (buffer.size < total) return Step.NeedMore

        if (code != 0) return Step.Failed(Socks5.replyMessage(code))

        stage = Stage.DONE
        val early = buffer.copyOfRange(total, buffer.size)
        buffer = ByteArray(0)
        return Step.Ready(early)
    }
}
