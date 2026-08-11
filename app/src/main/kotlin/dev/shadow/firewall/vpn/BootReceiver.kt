package dev.shadow.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import dev.shadow.firewall.FirewallApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Brings the firewall back up after a reboot or an app update, but only if the user asked
 * for that and consent is still on file.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

        val application = context.applicationContext as? FirewallApp ?: return
        val pending = goAsync()

        CoroutineScope(SupervisorJob() + Dispatchers.Default).launch {
            try {
                if (!application.ruleStore.settings.first().autoStartOnBoot) return@launch
                // VpnService.prepare returns an intent when consent is needed. A receiver
                // cannot show that prompt, so the only correct move is to stay down.
                if (VpnService.prepare(context) != null) {
                    Log.i(TAG, "not auto-starting: VPN consent is no longer granted")
                    return@launch
                }
                FirewallVpnService.start(context)
            } catch (error: Exception) {
                Log.w(TAG, "auto-start failed", error)
            } finally {
                pending.finish()
            }
        }
    }

    private companion object {
        const val TAG = "BootReceiver"
    }
}
