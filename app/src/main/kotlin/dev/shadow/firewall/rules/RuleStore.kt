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
        try {
            json.decodeFromString<StoredRules>(raw).toSettings()
        } catch (error: Exception) {
            Log.w(TAG, "stored rules were unreadable, falling back to defaults", error)
            FirewallSettings()
        }
    }

    suspend fun update(transform: (FirewallSettings) -> FirewallSettings) {
        context.dataStore.edit { preferences ->
            val current = preferences[KEY_RULES]
                ?.let {
                    runCatching { json.decodeFromString<StoredRules>(it).toSettings() }
                        .getOrDefault(FirewallSettings())
                }
                ?: FirewallSettings()
            preferences[KEY_RULES] = json.encodeToString(transform(current).toStored())
        }
    }

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
        it.copy(rules = RuleSet(blockIpv6 = it.rules.blockIpv6))
    }

    private fun parseDomains(text: String): Set<String> =
        RuleEngine.normaliseAll(text.split('\n', ',', ' ').filter { it.isNotBlank() })

    private fun StoredRules.toSettings() = FirewallSettings(
        rules = RuleSet(
            blockByDefault = blockByDefault,
            blockIpv6 = blockIpv6,
            appRules = apps.associate { it.uid to AppRule(it.uid, it.blockWifi, it.blockMobile) },
            allowedUids = allowedUids.toSet(),
            blockedDomains = RuleEngine.normaliseAll(blockedDomains),
            allowedDomains = RuleEngine.normaliseAll(allowedDomains),
        ),
        autoStartOnBoot = autoStartOnBoot,
    )

    private fun FirewallSettings.toStored() = StoredRules(
        blockByDefault = rules.blockByDefault,
        blockIpv6 = rules.blockIpv6,
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
