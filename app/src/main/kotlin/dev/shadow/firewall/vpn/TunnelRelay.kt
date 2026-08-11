package dev.shadow.firewall.vpn

import android.util.Log
import dev.shadow.firewall.core.ConnectionEvent
import dev.shadow.firewall.core.BlockReason
import dev.shadow.firewall.core.Dns
import dev.shadow.firewall.core.FlowKey
import dev.shadow.firewall.core.HostnameCache
import dev.shadow.firewall.core.IpPacket
import dev.shadow.firewall.core.IpProto
import dev.shadow.firewall.core.PacketFactory
import dev.shadow.firewall.core.RuleEngine
import dev.shadow.firewall.core.TcpSegment
import dev.shadow.firewall.core.UdpDatagram
import dev.shadow.firewall.core.Verdict
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Identifying details for an app, resolved lazily from a uid. */
data class AppIdentity(val packageName: String?, val label: String?)

/**
 * The heart of the firewall: reads every packet the system hands to the tun device, decides
 * whether the flow is allowed, and either relays it or refuses it.
 *
 * A verdict is reached once per flow rather than once per packet — at the SYN for TCP, at the
 * first datagram for UDP — because the uid lookup and hostname match are far too expensive to
 * run on every packet at line rate.
 */
class TunnelRelay(
    private val tunInput: FileInputStream,
    tunOutput: FileOutputStream,
    private val mtu: Int,
    private val ruleEngine: RuleEngine,
    private val hostnames: HostnameCache,
    private val uidResolver: UidResolver,
    private val networkMonitor: NetworkMonitor,
    private val identify: (Int) -> AppIdentity,
    private val onEvent: (ConnectionEvent) -> Unit,
    private val onBytes: (eventId: Long, sent: Long, received: Long) -> Unit,
    private val protectTcp: (SocketChannel) -> Boolean,
    private val protectUdp: (DatagramChannel) -> Boolean,
) {

    private val sink = TunWriter(tunOutput)
    private val selectorLoop = SelectorLoop()
    private val running = AtomicBoolean(false)
    private val nextEventId = AtomicLong(1)

    private val tcpFlows = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val udpFlows = ConcurrentHashMap<FlowKey, UdpFlow>()

    /** Blocked flows we have already logged, so a retrying app does not flood the log. */
    private val recentlyBlocked = ConcurrentHashMap<FlowKey, Long>()

    private var readerThread: Thread? = null
    private var sweeperThread: Thread? = null

    @Volatile var packetsSeen: Long = 0; private set
    @Volatile var flowsBlocked: Long = 0; private set
    @Volatile var flowsAllowed: Long = 0; private set

    fun start() {
        if (!running.compareAndSet(false, true)) return
        readerThread = Thread(::readLoop, "tun-reader").apply { isDaemon = true; start() }
        sweeperThread = Thread(::sweepLoop, "flow-sweeper").apply { isDaemon = true; start() }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        readerThread?.interrupt()
        sweeperThread?.interrupt()
        tcpFlows.values.forEach { it.close() }
        udpFlows.values.forEach { it.close() }
        tcpFlows.clear()
        udpFlows.clear()
        selectorLoop.stop()
        sink.stop()
        uidResolver.clear()
    }

    // -------------------------------------------------------------- reading

    private fun readLoop() {
        // One buffer reused for every packet; flows copy anything they need to keep.
        val buffer = ByteArray(mtu + HEADROOM)
        while (running.get()) {
            val read = try {
                tunInput.read(buffer)
            } catch (error: IOException) {
                if (running.get()) Log.w(TAG, "tun read failed", error)
                return
            }
            if (read <= 0) continue

            packetsSeen++
            try {
                dispatch(buffer, read)
            } catch (error: Exception) {
                // A malformed packet must never take the tunnel down.
                Log.w(TAG, "packet dispatch failed", error)
            }
        }
    }

    private fun dispatch(buffer: ByteArray, length: Int) {
        val packet = IpPacket.parse(buffer, 0, length) ?: return
        if (packet.fragmented) return // we do not reassemble; the sender will retry unfragmented

        when (packet.protocol) {
            IpProto.TCP -> packet.tcp()?.let { handleTcp(packet, it) }
            IpProto.UDP -> packet.udp()?.let { handleUdp(packet, it) }
            // ICMP and everything else is dropped: relaying it needs a raw socket, which a
            // non-root app cannot open. In practice this only costs ping.
            else -> Unit
        }
    }

    // -------------------------------------------------------------- tcp

    private fun handleTcp(packet: IpPacket, segment: TcpSegment) {
        val key = flowKey(IpProto.TCP, packet, segment.sourcePort, segment.destinationPort)

        tcpFlows[key]?.let { existing ->
            if (!existing.isClosed) {
                existing.onSegment(segment)
                return
            }
            tcpFlows.remove(key, existing)
        }

        if (!segment.isSyn) {
            // A segment for a flow we know nothing about. Resetting lets the app fail fast
            // instead of retransmitting into a tunnel that will never answer.
            if (!segment.isRst) sink.write(PacketFactory.buildRstFor(segment))
            return
        }

        val decision = judge(key, packet, segment.sourcePort, segment.destinationPort)
        if (decision.isBlocked) {
            sink.write(PacketFactory.buildRstFor(segment))
            return
        }

        val eventId = decision.eventId
        val flow = TcpFlow(
            key = key,
            eventId = eventId,
            appAddress = packet.sourceAddress,
            appPort = segment.sourcePort,
            remoteAddress = packet.destinationAddress,
            remotePort = segment.destinationPort,
            tunMss = PacketFactory.maxSegmentSize(mtu, packet.isIpv6),
            sink = sink,
            selectorLoop = selectorLoop,
            onBytes = { sent, received -> onBytes(eventId, sent, received) },
            onClosed = { closed ->
                tcpFlows.remove(closed.key, closed)
                uidResolver.forget(closed.key)
            },
        )
        tcpFlows[key] = flow
        flow.open(segment, protectTcp)
    }

    // -------------------------------------------------------------- udp

    private fun handleUdp(packet: IpPacket, datagram: UdpDatagram) {
        val key = flowKey(IpProto.UDP, packet, datagram.sourcePort, datagram.destinationPort)

        // DNS is inspected per query, not per flow: one socket to the resolver carries every
        // lookup an app makes, so a flow-level verdict would be far too coarse.
        if (datagram.destinationPort == UdpFlow.DNS_PORT &&
            interceptDnsQuery(packet, datagram, key)
        ) {
            return
        }

        udpFlows[key]?.let { existing ->
            if (!existing.isClosed) {
                existing.send(packet.data, datagram.payloadOffset, datagram.payloadLength)
                return
            }
            udpFlows.remove(key, existing)
        }

        val decision = judge(key, packet, datagram.sourcePort, datagram.destinationPort)
        if (decision.isBlocked) return // silently dropped; UDP senders expect loss

        val eventId = decision.eventId
        val flow = UdpFlow(
            key = key,
            eventId = eventId,
            appAddress = packet.sourceAddress,
            appPort = datagram.sourcePort,
            remoteAddress = packet.destinationAddress,
            remotePort = datagram.destinationPort,
            maxDatagram = MAX_DATAGRAM,
            sink = sink,
            selectorLoop = selectorLoop,
            onResponse = { flow, payload -> if (flow.isDns) recordDnsResponse(payload) },
            onBytes = { sent, received -> onBytes(eventId, sent, received) },
            onClosed = { closed ->
                udpFlows.remove(closed.key, closed)
                uidResolver.forget(closed.key)
            },
        )
        udpFlows[key] = flow
        if (flow.open(protectUdp)) {
            flow.send(packet.data, datagram.payloadOffset, datagram.payloadLength)
        } else {
            udpFlows.remove(key, flow)
        }
    }

    /**
     * Answers a lookup for a blocked domain with NXDOMAIN instead of forwarding it.
     *
     * Returns true when the query was handled here and must not be relayed.
     */
    private fun interceptDnsQuery(
        packet: IpPacket,
        datagram: UdpDatagram,
        key: FlowKey,
    ): Boolean {
        val message = Dns.parse(packet.data, datagram.payloadOffset, datagram.payloadLength)
            ?: return false
        if (message.isResponse) return false
        val name = message.queryName ?: return false

        val rules = ruleEngine.rules
        if (RuleEngine.matches(name, rules.allowedDomains)) return false
        if (!RuleEngine.matches(name, rules.blockedDomains)) return false

        val reply = Dns.buildNxDomain(packet.data, datagram.payloadOffset, datagram.payloadLength)
            ?: return false

        sink.write(
            PacketFactory.buildUdp(
                source = packet.destinationAddress,
                sourcePort = datagram.destinationPort,
                destination = packet.sourceAddress,
                destinationPort = datagram.sourcePort,
                payload = reply,
            ),
        )

        logBlockedLookup(key, packet, datagram, name)
        return true
    }

    private fun recordDnsResponse(payload: ByteArray) {
        val message = Dns.parse(payload) ?: return
        hostnames.record(message)
    }

    // -------------------------------------------------------------- verdicts

    private class Judgement(val isBlocked: Boolean, val eventId: Long)

    /** Resolves the owning app, applies the rules, and records the result in the log. */
    private fun judge(
        key: FlowKey,
        packet: IpPacket,
        sourcePort: Int,
        destinationPort: Int,
    ): Judgement {
        val uid = uidResolver.resolve(
            key,
            packet.sourceAddress,
            sourcePort,
            packet.destinationAddress,
            destinationPort,
        )
        val destination = key.destinationAddress
        val hostname = hostnames.get(destination)
        val network = networkMonitor.currentType
        val decision = ruleEngine.decide(uid, network, hostname, packet.isIpv6)

        if (decision.isBlocked) {
            flowsBlocked++
            // Retries of a blocked connection should not each produce a log entry.
            if (!shouldLogBlock(key)) return Judgement(true, 0)
        } else {
            flowsAllowed++
        }

        val identity = identify(uid)
        val eventId = nextEventId.getAndIncrement()
        val now = System.currentTimeMillis()
        onEvent(
            ConnectionEvent(
                id = eventId,
                startedAtMillis = now,
                updatedAtMillis = now,
                uid = uid,
                packageName = identity.packageName,
                appLabel = identity.label,
                protocol = key.protocol,
                destinationAddress = destination,
                destinationPort = destinationPort,
                hostname = hostname,
                network = network,
                verdict = decision.verdict,
                reason = decision.reason,
            ),
        )
        return Judgement(decision.isBlocked, eventId)
    }

    private fun logBlockedLookup(
        key: FlowKey,
        packet: IpPacket,
        datagram: UdpDatagram,
        name: String,
    ) {
        flowsBlocked++
        val lookupKey = key.copy(sourcePort = 0) // one entry per domain, not per query socket
        if (!shouldLogBlock(lookupKey)) return

        val uid = uidResolver.resolve(
            key,
            packet.sourceAddress,
            datagram.sourcePort,
            packet.destinationAddress,
            datagram.destinationPort,
        )
        val identity = identify(uid)
        val now = System.currentTimeMillis()
        onEvent(
            ConnectionEvent(
                id = nextEventId.getAndIncrement(),
                startedAtMillis = now,
                updatedAtMillis = now,
                uid = uid,
                packageName = identity.packageName,
                appLabel = identity.label,
                protocol = IpProto.UDP,
                destinationAddress = key.destinationAddress,
                destinationPort = datagram.destinationPort,
                hostname = name,
                network = networkMonitor.currentType,
                verdict = Verdict.BLOCK,
                reason = BlockReason.DOMAIN_BLOCKLIST,
            ),
        )
    }

    /** Rate-limits log entries for a flow the user has already been told about. */
    private fun shouldLogBlock(key: FlowKey): Boolean {
        val now = System.currentTimeMillis()
        val previous = recentlyBlocked[key]
        if (previous != null && now - previous < BLOCK_LOG_INTERVAL_MILLIS) return false
        recentlyBlocked[key] = now
        return true
    }

    // -------------------------------------------------------------- housekeeping

    private fun sweepLoop() {
        while (running.get()) {
            try {
                Thread.sleep(SWEEP_INTERVAL_MILLIS)
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
            val now = System.currentTimeMillis()

            for (flow in tcpFlows.values) {
                val limit = if (flow.isEstablished) TCP_IDLE_MILLIS else TCP_HANDSHAKE_MILLIS
                if (now - flow.lastActivityMillis > limit) flow.abort()
            }
            for (flow in udpFlows.values) {
                val limit = if (flow.isDns) DNS_IDLE_MILLIS else UDP_IDLE_MILLIS
                if (now - flow.lastActivityMillis > limit) flow.close()
            }
            recentlyBlocked.entries.removeAll { now - it.value > BLOCK_LOG_INTERVAL_MILLIS * 2 }
        }
    }

    private fun flowKey(
        protocol: Int,
        packet: IpPacket,
        sourcePort: Int,
        destinationPort: Int,
    ): FlowKey = FlowKey(
        protocol = protocol,
        sourceAddress = packet.sourceAddress.text(),
        sourcePort = sourcePort,
        destinationAddress = packet.destinationAddress.text(),
        destinationPort = destinationPort,
    )

    private fun InetAddress.text(): String = hostAddress ?: toString()

    private companion object {
        const val TAG = "TunnelRelay"

        /** Slack above the MTU so an oversized read is never silently truncated. */
        const val HEADROOM = 80
        const val MAX_DATAGRAM = 65535

        const val SWEEP_INTERVAL_MILLIS = 10_000L
        const val TCP_HANDSHAKE_MILLIS = 30_000L
        const val TCP_IDLE_MILLIS = 5 * 60_000L
        const val UDP_IDLE_MILLIS = 60_000L
        const val DNS_IDLE_MILLIS = 15_000L
        const val BLOCK_LOG_INTERVAL_MILLIS = 30_000L
    }
}
