package dev.shadow.firewall.core

/**
 * Where to find Tor on the device.
 *
 * This app does not contain Tor. It hands connections to Orbot, the Tor Project's own Android
 * client, over the SOCKS proxy Orbot listens on. Orbot must be installed and running; if it is
 * not, a routed connection fails rather than quietly going out in the clear.
 */
object Tor {

    /** Orbot, published by the Tor Project and the Guardian Project. */
    const val ORBOT_PACKAGE = "org.torproject.android"

    /** Orbot's SOCKS5 listener. Loopback only, so nothing off the device can reach it. */
    const val SOCKS_HOST = "127.0.0.1"
    const val SOCKS_PORT = 9050

    /**
     * How long to let a routed connection sit in its handshake.
     *
     * Building a circuit is slow the first time — Orbot may still be bootstrapping — so these
     * connections get far longer than a direct one before the sweeper gives up on them.
     */
    const val HANDSHAKE_TIMEOUT_MILLIS = 90_000L
}
