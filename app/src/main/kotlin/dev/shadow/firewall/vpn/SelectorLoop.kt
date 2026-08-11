package dev.shadow.firewall.vpn

import android.util.Log
import java.io.IOException
import java.nio.channels.CancelledKeyException
import java.nio.channels.SelectableChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

/** A flow that owns a channel registered with the [SelectorLoop]. */
interface SelectableFlow {
    /** Called on the selector thread once the channel is registered. */
    fun onRegistered(key: SelectionKey)

    /** Called on the selector thread whenever the channel is ready. */
    fun onSelected(key: SelectionKey)
}

/**
 * One thread driving every relayed socket.
 *
 * A phone can easily have a few hundred connections open at once, so a thread per flow is out
 * of the question. Registration and interest changes are funnelled through [pending] because
 * mutating a key while the selector thread sits in `select()` can block the caller.
 */
class SelectorLoop(name: String = "vpn-selector") {

    private val selector: Selector = Selector.open()
    private val pending = ConcurrentLinkedQueue<() -> Unit>()
    private val running = AtomicBoolean(true)

    private val thread = Thread({ loop() }, name).apply {
        isDaemon = true
        start()
    }

    fun register(channel: SelectableChannel, interestOps: Int, flow: SelectableFlow) {
        submit {
            try {
                val key = channel.register(selector, interestOps, flow)
                flow.onRegistered(key)
            } catch (error: Exception) {
                Log.d(TAG, "register failed: ${error.message}")
            }
        }
    }

    /** Queues [action] to run on the selector thread and nudges the selector awake. */
    fun submit(action: () -> Unit) {
        if (!running.get()) return
        pending.add(action)
        selector.wakeup()
    }

    fun wakeup() {
        selector.wakeup()
    }

    fun cancel(key: SelectionKey) {
        submit {
            try {
                key.cancel()
            } catch (ignored: Exception) {
            }
        }
    }

    private fun loop() {
        while (running.get()) {
            try {
                drainPending()
                if (selector.select(SELECT_TIMEOUT_MILLIS) == 0) continue

                val iterator = selector.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()
                    val flow = key.attachment() as? SelectableFlow ?: continue
                    try {
                        flow.onSelected(key)
                    } catch (ignored: CancelledKeyException) {
                        // The flow closed itself while we were dispatching.
                    } catch (error: Exception) {
                        Log.w(TAG, "flow dispatch failed", error)
                        try {
                            key.cancel()
                            key.channel().close()
                        } catch (ignored: IOException) {
                        }
                    }
                }
            } catch (error: IOException) {
                if (running.get()) Log.w(TAG, "selector loop error", error)
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
    }

    private fun drainPending() {
        while (true) {
            val action = pending.poll() ?: return
            try {
                action()
            } catch (error: Exception) {
                Log.w(TAG, "pending selector action failed", error)
            }
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        selector.wakeup()
        try {
            for (key in selector.keys()) {
                try {
                    key.channel().close()
                } catch (ignored: IOException) {
                }
            }
            selector.close()
        } catch (ignored: IOException) {
        }
        thread.interrupt()
    }

    private companion object {
        const val TAG = "SelectorLoop"
        const val SELECT_TIMEOUT_MILLIS = 1000L
    }
}
