package dev.shadow.firewall

import android.app.Application
import dev.shadow.firewall.core.HostnameCache
import dev.shadow.firewall.rules.AppRepository
import dev.shadow.firewall.rules.RuleStore
import dev.shadow.firewall.rules.TrafficLog

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
}
