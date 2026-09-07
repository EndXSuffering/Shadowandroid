package dev.shadow.firewall.rules

import android.content.Context
import android.util.Log
import dev.shadow.firewall.core.Blocklist
import dev.shadow.firewall.core.BlocklistIndex
import dev.shadow.firewall.core.BlocklistParser
import dev.shadow.firewall.core.DomainHashSet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/** What the UI needs to know about one subscribed list. */
data class BlocklistStatus(
    val source: BlocklistSource,
    val enabled: Boolean,
    val entryCount: Int = 0,
    val addressCount: Int = 0,
    val updatedAtMillis: Long = 0,
    val lastError: String? = null,
    val downloading: Boolean = false,
) {
    val hasData: Boolean get() = entryCount > 0 || addressCount > 0
}

/**
 * Downloads, caches and loads the subscribed blocklists.
 *
 * Each list goes through the network once and is then stored as a compact hash index, so
 * starting the tunnel does not mean re-parsing several megabytes of text. Downloads are
 * conditional: a list that has not changed since last time costs one 304 response.
 */
class BlocklistRepository(
    private val context: Context,
    private val store: RuleStore,
) {

    private val directory: File by lazy {
        File(context.filesDir, "blocklists").apply { mkdirs() }
    }

    private val _index = MutableStateFlow(BlocklistIndex.EMPTY)

    /** The loaded lists, ready for the rule engine. */
    val index: StateFlow<BlocklistIndex> = _index.asStateFlow()

    private val _statuses = MutableStateFlow<List<BlocklistStatus>>(emptyList())
    val statuses: StateFlow<List<BlocklistStatus>> = _statuses.asStateFlow()

    private val _refreshing = MutableStateFlow(false)
    val refreshing: StateFlow<Boolean> = _refreshing.asStateFlow()

    // -------------------------------------------------------------- loading

    /** Reads the cached indexes from disk into memory. Safe to call repeatedly. */
    suspend fun load() = withContext(Dispatchers.IO) {
        val settings = store.blocklistState()
        val lists = ArrayList<Blocklist>()

        for (source in BlocklistCatalog.sources) {
            if (source.id !in settings.enabledIds) continue
            val file = indexFile(source.id)
            if (!file.exists()) continue
            try {
                lists += readIndex(source, file)
            } catch (error: IOException) {
                // A truncated or stale-format cache is not worth keeping.
                Log.w(TAG, "discarding unreadable cache for ${source.id}: ${error.message}")
                file.delete()
                store.recordBlocklistFailure(source.id, "Cached copy was unreadable")
            }
        }

        _index.value = BlocklistIndex(lists)
        publishStatuses()
        Log.i(TAG, "loaded ${lists.size} lists, ${_index.value.totalEntries} entries")
    }

    /** Recomputes the status list the settings screen renders. */
    suspend fun publishStatuses() {
        val state = store.blocklistState()
        _statuses.value = BlocklistCatalog.sources.map { source ->
            val meta = state.metadata[source.id]
            BlocklistStatus(
                source = source,
                enabled = source.id in state.enabledIds,
                entryCount = meta?.entryCount ?: 0,
                addressCount = meta?.addressCount ?: 0,
                updatedAtMillis = meta?.updatedAtMillis ?: 0,
                lastError = meta?.lastError,
            )
        }
    }

    // ------------------------------------------------------------ refreshing

    /**
     * Downloads every enabled list that is due, then reloads the index.
     *
     * @param force ignore both the staleness check and the cached validators.
     * @return true when every enabled list ended up with usable data.
     */
    suspend fun refresh(force: Boolean = false): Boolean = withContext(Dispatchers.IO) {
        if (_refreshing.value) return@withContext false
        _refreshing.value = true
        try {
            val state = store.blocklistState()
            var allSucceeded = true

            for (source in BlocklistCatalog.sources) {
                if (source.id !in state.enabledIds) continue
                val meta = state.metadata[source.id]
                val cached = indexFile(source.id).exists()
                if (!force && cached && !isStale(meta?.updatedAtMillis ?: 0, state.frequency)) continue

                val ok = downloadOne(source, if (force) null else meta)
                if (!ok && !cached) allSucceeded = false
            }

            load()
            allSucceeded
        } finally {
            _refreshing.value = false
        }
    }

    private fun isStale(updatedAtMillis: Long, frequency: UpdateFrequency): Boolean {
        if (updatedAtMillis == 0L) return true
        if (!frequency.isAutomatic) return false
        val age = System.currentTimeMillis() - updatedAtMillis
        return age >= frequency.hours * 60 * 60 * 1000
    }

    private suspend fun downloadOne(source: BlocklistSource, meta: BlocklistMetadata?): Boolean {
        Log.i(TAG, "fetching ${source.id}")
        var connection: HttpURLConnection? = null
        return try {
            connection = (URL(source.url).openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MILLIS
                readTimeout = READ_TIMEOUT_MILLIS
                instanceFollowRedirects = true
                setRequestProperty("Accept-Encoding", "gzip")
                setRequestProperty("User-Agent", USER_AGENT)
                meta?.etag?.let { setRequestProperty("If-None-Match", it) }
                meta?.lastModified?.let { setRequestProperty("If-Modified-Since", it) }
            }

            when (val code = connection.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> {
                    // Nothing changed; just refresh the timestamp so we stop asking.
                    store.recordBlocklistUnchanged(source.id)
                    true
                }
                HttpURLConnection.HTTP_OK -> {
                    val counts = parseInto(connection, source)
                    store.recordBlocklistSuccess(
                        id = source.id,
                        etag = connection.getHeaderField("ETag"),
                        lastModified = connection.getHeaderField("Last-Modified"),
                        entryCount = counts.first,
                        addressCount = counts.second,
                    )
                    // A list can arrive intact and still leave us with nothing, if every rule
                    // in it uses a construct this app cannot express. Saying so beats leaving
                    // the row reading "not downloaded yet", which blames the wrong thing.
                    if (counts.first == 0 && counts.second == 0) {
                        store.recordBlocklistFailure(source.id, EMPTY_AFTER_PARSE)
                    }
                    true
                }
                else -> {
                    store.recordBlocklistFailure(source.id, "Server returned $code")
                    false
                }
            }
        } catch (error: Exception) {
            Log.w(TAG, "failed to fetch ${source.id}", error)
            store.recordBlocklistFailure(source.id, error.message ?: error.javaClass.simpleName)
            false
        } finally {
            connection?.disconnect()
        }
    }

    /** Streams the response straight into hash indexes and writes them out. Returns counts. */
    private fun parseInto(connection: HttpURLConnection, source: BlocklistSource): Pair<Int, Int> {
        val blocked = DomainHashSet.Builder(source.approximateEntries.coerceIn(1024, 4_000_000))
        val allowed = DomainHashSet.Builder(256)
        val addresses = DomainHashSet.Builder(256)

        val raw = BufferedInputStream(connection.inputStream)
        val stream = if (connection.contentEncoding?.contains("gzip", ignoreCase = true) == true) {
            GZIPInputStream(raw)
        } else {
            raw
        }

        BufferedReader(InputStreamReader(stream), READ_BUFFER).use { reader ->
            while (true) {
                val line = reader.readLine() ?: break
                val rule = BlocklistParser.parseLine(line) ?: continue
                when {
                    rule.kind == BlocklistParser.Kind.ADDRESS ->
                        if (!rule.isException) rule.values.forEach(addresses::add)
                    rule.isException -> rule.values.forEach(allowed::add)
                    else -> rule.values.forEach(blocked::add)
                }
            }
        }

        val blockedSet = blocked.build()
        val allowedSet = allowed.build()
        val addressSet = addresses.build()

        // Write to a temporary file and rename, so a download interrupted halfway cannot
        // leave a half-written index that the next start would load.
        val target = indexFile(source.id)
        val temporary = File(target.parentFile, "${target.name}.tmp")
        BufferedOutputStream(FileOutputStream(temporary)).use { out ->
            blockedSet.writeTo(out)
            allowedSet.writeTo(out)
            addressSet.writeTo(out)
        }
        if (!temporary.renameTo(target)) {
            temporary.delete()
            throw IOException("could not replace the index for ${source.id}")
        }

        return if (source.isAllowlist) {
            allowedSet.size to 0
        } else {
            blockedSet.size to addressSet.size
        }
    }

    private fun readIndex(source: BlocklistSource, file: File): Blocklist =
        BufferedInputStream(FileInputStream(file)).use { input ->
            Blocklist(
                id = source.id,
                title = source.title,
                blocked = DomainHashSet.readFrom(input),
                allowed = DomainHashSet.readFrom(input),
                blockedAddresses = DomainHashSet.readFrom(input),
                isAllowlist = source.isAllowlist,
            )
        }

    /** Drops a list's cached data, used when the user switches it off. */
    suspend fun forget(id: String) = withContext(Dispatchers.IO) {
        indexFile(id).delete()
        store.clearBlocklistMetadata(id)
        load()
    }

    private fun indexFile(id: String) = File(directory, "$id.idx")

    private companion object {
        const val TAG = "BlocklistRepository"
        const val CONNECT_TIMEOUT_MILLIS = 20_000
        const val READ_TIMEOUT_MILLIS = 60_000
        const val READ_BUFFER = 1 shl 16
        const val EMPTY_AFTER_PARSE = "Downloaded, but none of its rules apply at DNS level"
        const val USER_AGENT = "ShadowFirewall/1.0 (+https://github.com/EndXSuffering/Shadowandroid)"
    }
}
