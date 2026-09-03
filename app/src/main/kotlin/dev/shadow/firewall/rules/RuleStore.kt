package dev.shadow.firewall.rules

import android.content.Context
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dev.shadow.firewall.core.AppRule
import dev.shadow.firewall.core.RuleEngine
import dev.shadow.firewall.core.RuleSet
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "firewall_rules")

/** On-disk shape of the rules; kept separate from [RuleSet] so the format can evolve. */
@Serializable
private data class StoredRules(
    val version: Int = 1,
    val blockByDefault: Boolean = false,
    val blockIpv6: Boolean = false,
    val apps: List<StoredAppRule> = emptyList(),
    val allowedUids: List<Int> = emptyList(),
    val blockedDomains: List<String> = emptyList(),
    val allowedDomains: List<String> = emptyList(),
    val autoStartOnBoot: Boolean = false,
    val useBlocklists: Boolean = true,
    val blockEncryptedDns: Boolean = true,
    val bypassedPackages: List<String> = emptyList(),
    val torPackages: List<String> = emptyList(),
    /** Null means "never configured", which is how the defaults get applied exactly once. */
    val enabledBlocklists: List<String>? = null,
    val updateFrequency: String = UpdateFrequency.DAILY.name,
    val trackerProtection: String = TrackerProtection.BALANCED.name,
    val updateOnUnmeteredOnly: Boolean = true,
    val blocklistMetadata: Map<String, BlocklistMetadata> = emptyMap(),
)

/** Per-list download bookkeeping, so a refresh can be conditional and failures are visible. */
@Serializable
data class BlocklistMetadata(
    val etag: String? = null,
    val lastModified: String? = null,
    val updatedAtMillis: Long = 0,
    val entryCount: Int = 0,
    val addressCount: Int = 0,
    val lastError: String? = null,
)

/** Everything about the subscribed lists, read as a unit by the repository. */
data class BlocklistState(
    val enabledIds: Set<String>,
    val frequency: UpdateFrequency,
    val unmeteredOnly: Boolean,
    val metadata: Map<String, BlocklistMetadata>,
)

@Serializable
private data class StoredAppRule(
    val uid: Int,
    val blockWifi: Boolean = false,
    val blockMobile: Boolean = false,
)

/** Everything the user has configured, including preferences that are not firewall rules. */
data class FirewallSettings(
    val rules: RuleSet = RuleSet(),
    val autoStartOnBoot: Boolean = false,
    val enabledBlocklists: Set<String> = BlocklistCatalog.defaultEnabledIds,
    val updateFrequency: UpdateFrequency = UpdateFrequency.DAILY,
    val updateOnUnmeteredOnly: Boolean = true,
    val trackerProtection: TrackerProtection = TrackerProtection.BALANCED,
)

/**
 * Persists the firewall configuration.
 *
 * Rules are stored as a single JSON document rather than as individual preference keys: they
 * are always read and written as a unit, and one document keeps a partially applied update
 * from ever being observed by the tunnel.
 */
class RuleStore(private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    val settings: Flow<FirewallSettings> = context.dataStore.data.map { preferences ->
        val raw = preferences[KEY_RULES] ?: return@map FirewallSettings()
        decode(raw)?.toSettings() ?: FirewallSettings()
    }

    suspend fun update(transform: (FirewallSettings) -> FirewallSettings) = editStored { stored ->
        // Metadata is not part of FirewallSettings, so carry it across untouched.
        transform(stored.toSettings()).toStored().copy(blocklistMetadata = stored.blocklistMetadata)
    }

    /** Reads, transforms and writes the stored document under the DataStore lock. */
    private suspend fun editStored(transform: (StoredRules) -> StoredRules) {
        context.dataStore.edit { preferences ->
            val current = preferences[KEY_RULES]?.let { decode(it) } ?: StoredRules()
            preferences[KEY_RULES] = json.encodeToString(transform(current))
        }
    }

    private suspend fun readStored(): StoredRules =
        context.dataStore.data.first().let { preferences ->
            preferences[KEY_RULES]?.let { decode(it) } ?: StoredRules()
        }

    private fun decode(raw: String): StoredRules? = try {
        json.decodeFromString<StoredRules>(raw)
    } catch (error: Exception) {
        Log.w(TAG, "stored rules were unreadable, falling back to defaults", error)
        null
    }

    private fun parseFrequency(name: String): UpdateFrequency =
        runCatching { UpdateFrequency.valueOf(name) }.getOrDefault(UpdateFrequency.DAILY)

    private fun parseTrackerProtection(name: String): TrackerProtection =
        runCatching { TrackerProtection.valueOf(name) }.getOrDefault(TrackerProtection.BALANCED)

    suspend fun setAppRule(rule: AppRule) = update { it.copy(rules = it.rules.withAppRule(rule)) }

    suspend fun setBlockByDefault(enabled: Boolean) =
        update { it.copy(rules = it.rules.copy(blockByDefault = enabled)) }

    suspend fun setBlockIpv6(enabled: Boolean) =
        update { it.copy(rules = it.rules.copy(blockIpv6 = enabled)) }

    suspend fun setAutoStartOnBoot(enabled: Boolean) = update { it.copy(autoStartOnBoot = enabled) }

    /** Replaces the blocklist from newline- or comma-separated text. */
    suspend fun setBlockedDomains(text: String) = update {
        it.copy(rules = it.rules.copy(blockedDomains = parseDomains(text)))
    }

    suspend fun setAllowedDomains(text: String) = update {
        it.copy(rules = it.rules.copy(allowedDomains = parseDomains(text)))
    }

    suspend fun addBlockedDomain(domain: String) = update {
        val normalised = RuleEngine.normalise(domain)
        if (normalised.isEmpty()) it
        else it.copy(rules = it.rules.copy(blockedDomains = it.rules.blockedDomains + normalised))
    }

    suspend fun clearAllRules() = update {
        it.copy(
            rules = RuleSet(
                blockIpv6 = it.rules.blockIpv6,
                useBlocklists = it.rules.useBlocklists,
                blockEncryptedDns = it.rules.blockEncryptedDns,
                bypassedPackages = it.rules.bypassedPackages,
                torPackages = it.rules.torPackages,
            ),
        )
    }

    // ------------------------------------------------------------ blocklists

    suspend fun setUseBlocklists(enabled: Boolean) =
        update { it.copy(rules = it.rules.copy(useBlocklists = enabled)) }

    suspend fun setBlockEncryptedDns(enabled: Boolean) =
        update { it.copy(rules = it.rules.copy(blockEncryptedDns = enabled)) }

    suspend fun setBypassed(packageName: String, bypassed: Boolean) =
        update { it.copy(rules = it.rules.withBypass(packageName, bypassed)) }

    suspend fun setTorRouted(packageName: String, routed: Boolean) =
        update { it.copy(rules = it.rules.withTorRouting(packageName, routed)) }

    suspend fun setBlocklistEnabled(id: String, enabled: Boolean) = update {
        val next = it.enabledBlocklists.toMutableSet()
        if (enabled) next.add(id) else next.remove(id)
        it.copy(enabledBlocklists = next)
    }

    suspend fun setUpdateFrequency(frequency: UpdateFrequency) =
        update { it.copy(updateFrequency = frequency) }

    /**
     * Applies a tracker level, which is a shorthand for a particular set of lists. Lists
     * outside the tracker feature are left exactly as the user set them.
     */
    suspend fun setTrackerProtection(level: TrackerProtection) = update { settings ->
        val trackerIds = BlocklistCatalog.trackerSources.map { it.id }.toSet()
        val wanted = BlocklistCatalog.trackerIdsFor(level)
        settings.copy(
            trackerProtection = level,
            enabledBlocklists = settings.enabledBlocklists - trackerIds + wanted,
        )
    }

    suspend fun setUpdateOnUnmeteredOnly(enabled: Boolean) =
        update { it.copy(updateOnUnmeteredOnly = enabled) }

    /** A snapshot for the repository, which needs the metadata the settings flow omits. */
    suspend fun blocklistState(): BlocklistState {
        val stored = readStored()
        return BlocklistState(
            enabledIds = stored.enabledBlocklists?.toSet() ?: BlocklistCatalog.defaultEnabledIds,
            frequency = parseFrequency(stored.updateFrequency),
            unmeteredOnly = stored.updateOnUnmeteredOnly,
            metadata = stored.blocklistMetadata,
        )
    }

    suspend fun recordBlocklistSuccess(
        id: String,
        etag: String?,
        lastModified: String?,
        entryCount: Int,
        addressCount: Int,
    ) = updateMetadata(id) {
        BlocklistMetadata(
            etag = etag,
            lastModified = lastModified,
            updatedAtMillis = System.currentTimeMillis(),
            entryCount = entryCount,
            addressCount = addressCount,
            lastError = null,
        )
    }

    /** A 304: the data we already hold is current, so only the timestamp moves. */
    suspend fun recordBlocklistUnchanged(id: String) = updateMetadata(id) { previous ->
        (previous ?: BlocklistMetadata()).copy(
            updatedAtMillis = System.currentTimeMillis(),
            lastError = null,
        )
    }

    suspend fun recordBlocklistFailure(id: String, message: String) = updateMetadata(id) { previous ->
        // Keep the counts and validators: a failed refresh does not invalidate what we have.
        (previous ?: BlocklistMetadata()).copy(lastError = message)
    }

    suspend fun clearBlocklistMetadata(id: String) = editStored { stored ->
        stored.copy(blocklistMetadata = stored.blocklistMetadata - id)
    }

    private suspend fun updateMetadata(
        id: String,
        transform: (BlocklistMetadata?) -> BlocklistMetadata,
    ) = editStored { stored ->
        stored.copy(
            blocklistMetadata = stored.blocklistMetadata + (id to transform(stored.blocklistMetadata[id])),
        )
    }

    private fun parseDomains(text: String): Set<String> =
        RuleEngine.normaliseAll(text.split('\n', ',', ' ').filter { it.isNotBlank() })

    private fun StoredRules.toSettings() = FirewallSettings(
        rules = RuleSet(
            blockByDefault = blockByDefault,
            blockIpv6 = blockIpv6,
            useBlocklists = useBlocklists,
            blockEncryptedDns = blockEncryptedDns,
            bypassedPackages = bypassedPackages.toSet(),
            torPackages = torPackages.toSet(),
            appRules = apps.associate { it.uid to AppRule(it.uid, it.blockWifi, it.blockMobile) },
            allowedUids = allowedUids.toSet(),
            blockedDomains = RuleEngine.normaliseAll(blockedDomains),
            allowedDomains = RuleEngine.normaliseAll(allowedDomains),
        ),
        autoStartOnBoot = autoStartOnBoot,
        enabledBlocklists = enabledBlocklists?.toSet() ?: BlocklistCatalog.defaultEnabledIds,
        updateFrequency = parseFrequency(updateFrequency),
        updateOnUnmeteredOnly = updateOnUnmeteredOnly,
        trackerProtection = parseTrackerProtection(trackerProtection),
    )

    private fun FirewallSettings.toStored() = StoredRules(
        blockByDefault = rules.blockByDefault,
        blockIpv6 = rules.blockIpv6,
        useBlocklists = rules.useBlocklists,
        blockEncryptedDns = rules.blockEncryptedDns,
        bypassedPackages = rules.bypassedPackages.toList().sorted(),
        torPackages = rules.torPackages.toList().sorted(),
        enabledBlocklists = enabledBlocklists.toList().sorted(),
        updateFrequency = updateFrequency.name,
        updateOnUnmeteredOnly = updateOnUnmeteredOnly,
        trackerProtection = trackerProtection.name,
        apps = rules.appRules.values.map { StoredAppRule(it.uid, it.blockWifi, it.blockMobile) },
        allowedUids = rules.allowedUids.toList(),
        blockedDomains = rules.blockedDomains.toList().sorted(),
        allowedDomains = rules.allowedDomains.toList().sorted(),
        autoStartOnBoot = autoStartOnBoot,
    )

    private companion object {
        const val TAG = "RuleStore"
        val KEY_RULES = stringPreferencesKey("rules_json")
    }
}
