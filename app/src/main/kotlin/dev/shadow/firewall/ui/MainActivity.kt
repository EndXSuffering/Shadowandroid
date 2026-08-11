package dev.shadow.firewall.ui

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.shadow.firewall.R
import dev.shadow.firewall.vpn.FirewallVpnService

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ShadowFirewallTheme {
                Surface {
                    FirewallApp()
                }
            }
        }
    }
}

private enum class Tab(val labelRes: Int, val icon: ImageVector) {
    Apps(R.string.tab_apps, Icons.Filled.Apps),
    Traffic(R.string.tab_traffic, Icons.Filled.SwapVert),
    Settings(R.string.tab_settings, Icons.Filled.Settings),
}

@Composable
private fun FirewallApp(viewModel: FirewallViewModel = viewModel()) {
    val context = LocalContext.current
    var tab by rememberSaveable { mutableStateOf(Tab.Apps) }
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()

    // Starting a VPN needs a one-time system consent dialog; the result comes back here.
    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            FirewallVpnService.start(context)
        }
    }

    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* The tunnel runs either way; without it the status notification is just hidden. */ }

    val requestStart = remember {
        {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
            val consent: Intent? = VpnService.prepare(context)
            if (consent != null) consentLauncher.launch(consent) else FirewallVpnService.start(context)
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                for (entry in Tab.entries) {
                    NavigationBarItem(
                        selected = tab == entry,
                        onClick = { tab = entry },
                        icon = { Icon(entry.icon, contentDescription = null) },
                        label = { Text(stringResource(entry.labelRes)) },
                    )
                }
            }
        },
    ) { padding ->
        val content = Modifier.padding(padding)
        when (tab) {
            Tab.Apps -> AppsScreen(
                viewModel = viewModel,
                vpnRunning = vpnState.isRunning,
                onStart = requestStart,
                onStop = { FirewallVpnService.stop(context) },
                modifier = content,
            )
            Tab.Traffic -> TrafficScreen(
                viewModel = viewModel,
                vpnRunning = vpnState.isRunning,
                modifier = content,
            )
            Tab.Settings -> SettingsScreen(viewModel = viewModel, modifier = content)
        }
    }
}
