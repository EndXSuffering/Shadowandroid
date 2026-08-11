package dev.shadow.firewall.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.shadow.firewall.FirewallApp
import dev.shadow.firewall.core.AppRule
import dev.shadow.firewall.core.ConnectionEvent
import dev.shadow.firewall.core.NetworkType
import dev.shadow.firewall.core.Verdict
import dev.shadow.firewall.rules.FirewallSettings
import dev.shadow.firewall.rules.InstalledApp
import dev.shadow.firewall.vpn.FirewallVpnService
import dev.shadow.firewall.vpn.VpnState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** What the traffic screen is currently showing. */
enum class TrafficFilter { ALL, BLOCKED, ALLOWED }

data class AppListItem(
    val app: InstalledApp,
    val rule: AppRule,
)

class FirewallViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as FirewallApp

    val vpnState: StateFlow<VpnState> = FirewallVpnService.state

    val settings: StateFlow<FirewallSettings> = app.ruleStore.settings
        .stateIn(viewModelScope, SharingStarted.Eagerly, FirewallSettings())

    private val _installedApps = MutableStateFlow<List<InstalledApp>>(emptyList())

    private val _appQuery = MutableStateFlow("")
    val appQuery: StateFlow<String> = _appQuery.asStateFlow()

    private val _showSystemApps = MutableStateFlow(false)
    val showSystemApps: StateFlow<Boolean> = _showSystemApps.asStateFlow()

    private val _trafficFilter = MutableStateFlow(TrafficFilter.ALL)
    val trafficFilter: StateFlow<TrafficFilter> = _trafficFilter.asStateFlow()

    private val _loadingApps = MutableStateFlow(true)
    val loadingApps: StateFlow<Boolean> = _loadingApps.asStateFlow()

    /** The app list, filtered by the search box and the system-app toggle. */
    val apps: StateFlow<List<AppListItem>> =
        combine(_installedApps, settings, _appQuery, _showSystemApps) { installed, config, query, showSystem ->
            val needle = query.trim().lowercase()
            installed.asSequence()
                .filter { showSystem || !it.isSystem }
                .filter {
                    needle.isEmpty() ||
                        it.label.lowercase().contains(needle) ||
                        it.packageNames.any { name -> name.contains(needle) }
                }
                .map { AppListItem(it, config.rules.ruleFor(it.uid)) }
                .toList()
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val traffic: StateFlow<List<ConnectionEvent>> =
        combine(app.trafficLog.events, _trafficFilter) { events, filter ->
            when (filter) {
                TrafficFilter.ALL -> events
                TrafficFilter.BLOCKED -> events.filter { it.verdict == Verdict.BLOCK }
                TrafficFilter.ALLOWED -> events.filter { it.verdict == Verdict.ALLOW }
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    init {
        refreshApps()
    }

    fun refreshApps() {
        viewModelScope.launch {
            _loadingApps.value = true
            app.appRepository.invalidate()
            _installedApps.value = app.appRepository.loadApps()
            _loadingApps.value = false
        }
    }

    fun iconFor(packageName: String) = app.appRepository.icon(packageName)

    // -------------------------------------------------------------- rules

    fun toggleBlock(uid: Int, network: NetworkType, blocked: Boolean) {
        viewModelScope.launch {
            val current = settings.value.rules.ruleFor(uid)
            val updated = when (network) {
                NetworkType.WIFI -> current.copy(blockWifi = blocked)
                NetworkType.MOBILE -> current.copy(blockMobile = blocked)
                NetworkType.OTHER -> current.copy(blockWifi = blocked, blockMobile = blocked)
            }
            app.ruleStore.setAppRule(updated)
        }
    }

    /** Blocks an app on every network, used by the one-tap action in the traffic log. */
    fun blockEverywhere(uid: Int) {
        viewModelScope.launch {
            app.ruleStore.setAppRule(AppRule(uid, blockWifi = true, blockMobile = true))
        }
    }

    fun blockDomain(hostname: String) {
        viewModelScope.launch { app.ruleStore.addBlockedDomain(hostname) }
    }

    fun setBlockByDefault(enabled: Boolean) {
        viewModelScope.launch { app.ruleStore.setBlockByDefault(enabled) }
    }

    fun setBlockIpv6(enabled: Boolean) {
        viewModelScope.launch { app.ruleStore.setBlockIpv6(enabled) }
    }

    fun setAutoStartOnBoot(enabled: Boolean) {
        viewModelScope.launch { app.ruleStore.setAutoStartOnBoot(enabled) }
    }

    fun setBlockedDomains(text: String) {
        viewModelScope.launch { app.ruleStore.setBlockedDomains(text) }
    }

    fun setAllowedDomains(text: String) {
        viewModelScope.launch { app.ruleStore.setAllowedDomains(text) }
    }

    fun clearAllRules() {
        viewModelScope.launch { app.ruleStore.clearAllRules() }
    }

    // -------------------------------------------------------------- view state

    fun setAppQuery(query: String) { _appQuery.value = query }
    fun setShowSystemApps(show: Boolean) { _showSystemApps.value = show }
    fun setTrafficFilter(filter: TrafficFilter) { _trafficFilter.value = filter }
    fun clearTraffic() = app.trafficLog.clear()
}
