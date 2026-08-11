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
class TrafficLog(private val capacity: Int = 1000) {

    private val lock = Any()
    private val entries = ArrayDeque<ConnectionEvent>()
    private val byId = HashMap<Long, ConnectionEvent>()
    private var dirty = false

    private val _events = MutableStateFlow<List<ConnectionEvent>>(emptyList())
    val events: StateFlow<List<ConnectionEvent>> = _events.asStateFlow()

    fun record(event: ConnectionEvent) {
        synchronized(lock) {
            entries.addFirst(event)
            byId[event.id] = event
            while (entries.size > capacity) {
                byId.remove(entries.removeLast().id)
            }
            dirty = true
        }
    }

    /** Updates the byte counters for a flow that is already in the log. */
    fun recordBytes(eventId: Long, sent: Long, received: Long) {
        synchronized(lock) {
            val existing = byId[eventId] ?: return
            if (existing.bytesOut == sent && existing.bytesIn == received) return
            byId[eventId] = existing.copy(
                bytesOut = sent,
                bytesIn = received,
                updatedAtMillis = System.currentTimeMillis(),
            )
            dirty = true
        }
    }

    /** Pushes accumulated changes to observers. Cheap and safe to call when nothing changed. */
    fun publish() {
        val snapshot = synchronized(lock) {
            if (!dirty) return
            dirty = false
            // The deque holds insertion order; byId holds the freshest counters.
            entries.map { byId[it.id] ?: it }
        }
        _events.value = snapshot
    }

    fun clear() {
        synchronized(lock) {
            entries.clear()
            byId.clear()
            dirty = false
        }
        _events.value = emptyList()
    }
}
