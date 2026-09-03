package dev.shadow.firewall

import android.app.Application
import dev.shadow.firewall.core.HostnameCache
import dev.shadow.firewall.rules.AppRepository
import dev.shadow.firewall.rules.BlocklistRepository
import dev.shadow.firewall.rules.BlocklistWorker
import dev.shadow.firewall.rules.RuleStore
import dev.shadow.firewall.rules.TorGateway
import dev.shadow.firewall.rules.TrafficLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Holds the few pieces of state that the service and the UI both need.
 *
 * The traffic log and hostname cache live here rather than in the service because the UI must
 * still be able to show the last session's activity after the tunnel is switched off.
 */
class FirewallApp : Application() {

    val ruleStore: RuleStore by lazy { RuleStore(this) }
    val appRepository: AppRepository by lazy { AppRepository(this) }
    val trafficLog: TrafficLog by lazy { TrafficLog() }
    val hostnameCache: HostnameCache by lazy { HostnameCache() }
    val blocklistRepository: BlocklistRepository by lazy { BlocklistRepository(this, ruleStore) }
    val torGateway: TorGateway by lazy { TorGateway(this) }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        scope.launch {
            // Load whatever is already cached before anything asks for a verdict, then make
            // sure the periodic refresh matches the user's current preference.
            blocklistRepository.load()
            val state = ruleStore.blocklistState()
            BlocklistWorker.schedule(this@FirewallApp, state.frequency, state.unmeteredOnly)
            // First run has no cache at all, so fetch immediately rather than waiting a day.
            if (blocklistRepository.index.value.isEmpty) blocklistRepository.refresh()
        }
    }
}
