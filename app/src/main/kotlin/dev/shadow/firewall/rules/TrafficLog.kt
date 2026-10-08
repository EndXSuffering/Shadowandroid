package dev.shadow.firewall.rules

import dev.shadow.firewall.core.ConnectionEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.ArrayDeque

/**
 * The in-memory traffic log behind the live view.
 *
 * Entries are deliberately not persisted: it is a firewall log for the last few minutes of
 * activity, and writing a record of every connection the device makes to disk would create a
 * more sensitive artefact than the app is worth.
 *
 * Byte counters arrive per packet, which is far too often to redraw the UI, so updates are
 * accumulated and published only when [publish] is called on a timer.
 */
class TrafficLog(
    private val capacity: Int = 1000,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    /**
     * Running byte counts for one entry, updated in place.
     *
     * [recordBytes] runs once per relayed packet, on the tunnel's busiest threads. It used to
     * copy the whole event to change two numbers, an allocation per packet for a value nobody
     * reads until the next redraw. Counts now land here, and an event is copied at most once
     * per [publish], and only if its counts moved.
     */
    private class Counters(var bytesOut: Long, var bytesIn: Long) {
        var updatedAtMillis = 0L
        var changed = false
    }

    private val lock = Any()
    private val entries = ArrayDeque<ConnectionEvent>()
    private val byId = HashMap<Long, ConnectionEvent>()
    private val counters = HashMap<Long, Counters>()
    private var dirty = false

    private val _events = MutableStateFlow<List<ConnectionEvent>>(emptyList())
    val events: StateFlow<List<ConnectionEvent>> = _events.asStateFlow()

    fun record(event: ConnectionEvent) {
        synchronized(lock) {
            entries.addFirst(event)
            byId[event.id] = event
            counters[event.id] = Counters(event.bytesOut, event.bytesIn)
            while (entries.size > capacity) {
                val evicted = entries.removeLast().id
                byId.remove(evicted)
                counters.remove(evicted)
            }
            dirty = true
        }
    }

    /** Updates the byte counters for a flow that is already in the log. */
    fun recordBytes(eventId: Long, sent: Long, received: Long) {
        synchronized(lock) {
            val counts = counters[eventId] ?: return
            if (counts.bytesOut == sent && counts.bytesIn == received) return
            counts.bytesOut = sent
            counts.bytesIn = received
            counts.updatedAtMillis = clock()
            counts.changed = true
            dirty = true
        }
    }

    /** Pushes accumulated changes to observers. Cheap and safe to call when nothing changed. */
    fun publish() {
        val snapshot = synchronized(lock) {
            if (!dirty) return
            dirty = false
            for ((id, counts) in counters) {
                if (!counts.changed) continue
                counts.changed = false
                val event = byId[id] ?: continue
                byId[id] = event.copy(
                    bytesOut = counts.bytesOut,
                    bytesIn = counts.bytesIn,
                    updatedAtMillis = counts.updatedAtMillis,
                )
            }
            // The deque holds insertion order; byId holds the freshest counters.
            entries.map { byId[it.id] ?: it }
        }
        _events.value = snapshot
    }

    fun clear() {
        synchronized(lock) {
            entries.clear()
            byId.clear()
            counters.clear()
            dirty = false
        }
        _events.value = emptyList()
    }
}
