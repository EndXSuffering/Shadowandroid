package dev.shadow.firewall.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.shadow.firewall.R
import dev.shadow.firewall.core.NetworkType
import dev.shadow.firewall.rules.TorAvailability

/**
 * The per-app rule list: one row per uid, with a Wi-Fi and a mobile-data toggle.
 *
 * Toggling means "block", not "allow", so an untouched list is a firewall that lets
 * everything through — the safe default for something that can break every app on the phone.
 */
@Composable
fun AppsScreen(
    viewModel: FirewallViewModel,
    vpnRunning: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val apps by viewModel.apps.collectAsStateWithLifecycle()
    val query by viewModel.appQuery.collectAsStateWithLifecycle()
    val showSystem by viewModel.showSystemApps.collectAsStateWithLifecycle()
    val loading by viewModel.loadingApps.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val torAvailability by viewModel.torAvailability.collectAsStateWithLifecycle()
    var detail by remember { mutableStateOf<AppListItem?>(null) }

    Column(modifier.fillMaxSize()) {
        StatusHeader(vpnRunning = vpnRunning, onStart = onStart, onStop = onStop)

        OutlinedTextField(
            value = query,
            onValueChange = viewModel::setAppQuery,
            label = { Text(stringResource(R.string.search_apps)) },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
        )

        Row(
            Modifier.padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = showSystem,
                onClick = { viewModel.setShowSystemApps(!showSystem) },
                label = { Text(stringResource(R.string.show_system_apps)) },
            )
            Spacer(Modifier.weight(1f))
            Text(
                text = stringResource(R.string.app_count, apps.size),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.align(Alignment.CenterVertically),
            )
        }

        if (loading && apps.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Column
        }

        LazyColumn(
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(apps, key = { it.app.uid }) { item ->
                AppRow(
                    item = item,
                    icon = viewModel.iconFor(item.app.primaryPackage),
                    bypassed = item.app.packageNames.any(settings.rules::isBypassed),
                    torRouted = item.app.packageNames.any(settings.rules::isTorRouted),
                    onToggle = { network, blocked ->
                        viewModel.toggleBlock(item.app.uid, network, blocked)
                    },
                    onOpen = {
                        detail = item
                        viewModel.checkTor()
                    },
                )
            }
        }
    }

    detail?.let { item ->
        AppDetailDialog(
            item = item,
            bypassed = item.app.packageNames.any(settings.rules::isBypassed),
            torRouted = item.app.packageNames.any(settings.rules::isTorRouted),
            torAvailability = torAvailability,
            isDefaultSmsApp = item.app.isDefaultSms,
            onBypass = { bypass ->
                // A uid can cover several packages; exclude every one of them or the app
                // keeps a route into the tunnel through whichever was left behind.
                item.app.packageNames.forEach { viewModel.setBypassed(it, bypass) }
            },
            onTorRouted = { routed ->
                item.app.packageNames.forEach { viewModel.setTorRouted(it, routed) }
            },
            onOpenOrbot = viewModel::openOrbot,
            onDismiss = { detail = null },
        )
    }
}

/**
 * Explains what excluding an app means before the user does it. Bypass is a subtle idea —
 * the app is neither blocked nor filtered nor logged, it simply stops being visible — and a
 * switch on the list row would give no room to say so.
 */
@Composable
private fun AppDetailDialog(
    item: AppListItem,
    bypassed: Boolean,
    torRouted: Boolean,
    torAvailability: TorAvailability,
    isDefaultSmsApp: Boolean,
    onBypass: (Boolean) -> Unit,
    onTorRouted: (Boolean) -> Unit,
    onOpenOrbot: () -> Unit,
    onDismiss: () -> Unit,
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(item.app.label) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text = item.app.packageNames.joinToString("\n"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (isDefaultSmsApp) {
                    Text(
                        text = stringResource(R.string.bypass_sms_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }

                SwitchRow(
                    title = stringResource(R.string.tor_title),
                    summary = stringResource(R.string.tor_summary),
                    checked = torRouted,
                    onCheckedChange = onTorRouted,
                )
                TorNotice(
                    routed = torRouted,
                    availability = torAvailability,
                    onOpenOrbot = onOpenOrbot,
                )

                HorizontalDivider()

                SwitchRow(
                    title = stringResource(R.string.bypass_title),
                    summary = stringResource(R.string.bypass_summary),
                    checked = bypassed,
                    onCheckedChange = onBypass,
                )
                if (bypassed) {
                    Text(
                        stringResource(R.string.bypass_active_warning),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_close))
            }
        },
    )
}

@Composable
private fun SwitchRow(
    title: String,
    summary: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

/**
 * What Tor routing will and will not do for this app, plus whether Orbot is in a state to
 * carry it. Both halves matter: a routed app with Orbot stopped simply has no network, and a
 * routed app with Orbot running is still not anonymous, which is the more common misreading.
 */
@Composable
private fun TorNotice(
    routed: Boolean,
    availability: TorAvailability,
    onOpenOrbot: () -> Unit,
) {
    if (!routed) {
        Text(
            stringResource(R.string.tor_explainer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }

    Text(
        stringResource(R.string.tor_limits),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    when (availability) {
        TorAvailability.READY -> Text(
            stringResource(R.string.tor_orbot_ready),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
        )
        TorAvailability.UNKNOWN -> Unit
        TorAvailability.NOT_INSTALLED, TorAvailability.NOT_RUNNING -> {
            Text(
                stringResource(
                    if (availability == TorAvailability.NOT_INSTALLED) {
                        R.string.tor_orbot_missing
                    } else {
                        R.string.tor_orbot_stopped
                    },
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            androidx.compose.material3.TextButton(onClick = onOpenOrbot) {
                Text(
                    stringResource(
                        if (availability == TorAvailability.NOT_INSTALLED) {
                            R.string.action_install_orbot
                        } else {
                            R.string.action_open_orbot
                        },
                    ),
                )
            }
        }
    }
}

@Composable
private fun StatusHeader(vpnRunning: Boolean, onStart: () -> Unit, onStop: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth().padding(16.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = stringResource(
                        if (vpnRunning) R.string.status_running else R.string.status_stopped,
                    ),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = stringResource(
                        if (vpnRunning) R.string.status_running_detail
                        else R.string.status_stopped_detail,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(12.dp))
            Button(onClick = if (vpnRunning) onStop else onStart) {
                Text(stringResource(if (vpnRunning) R.string.action_stop else R.string.action_start))
            }
        }
    }
}

@Composable
private fun AppRow(
    item: AppListItem,
    icon: android.graphics.drawable.Drawable?,
    bypassed: Boolean,
    torRouted: Boolean,
    onToggle: (NetworkType, Boolean) -> Unit,
    onOpen: () -> Unit,
) {
    ElevatedCard(Modifier.fillMaxWidth().clickable(onClick = onOpen)) {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppIcon(icon)
            Spacer(Modifier.width(12.dp))

            Column(Modifier.weight(1f)) {
                Text(
                    text = item.app.label,
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = if (item.app.sharesUid) {
                        stringResource(
                            R.string.shared_uid_summary,
                            item.app.primaryPackage,
                            item.app.packageNames.size - 1,
                        )
                    } else {
                        item.app.primaryPackage
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (item.app.isDefaultSms) {
                    // Named on the row, not just inside the dialog: someone looking for it is
                    // scanning the list for a label they recognise, which may not be "Messages".
                    Text(
                        text = stringResource(R.string.messaging_app_marker),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }

            if (bypassed) {
                // A bypassed app is outside the tunnel, so the block switches cannot apply.
                Text(
                    text = stringResource(R.string.bypass_badge),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                return@Row
            }

            if (torRouted) {
                Text(
                    text = stringResource(R.string.tor_badge),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
                Spacer(Modifier.width(8.dp))
            }

            BlockToggle(
                icon = Icons.Filled.Wifi,
                description = stringResource(R.string.block_wifi),
                blocked = item.rule.blockWifi,
                onChange = { onToggle(NetworkType.WIFI, it) },
            )
            BlockToggle(
                icon = Icons.Filled.SignalCellularAlt,
                description = stringResource(R.string.block_mobile),
                blocked = item.rule.blockMobile,
                onChange = { onToggle(NetworkType.MOBILE, it) },
            )
        }
    }
}

@Composable
private fun BlockToggle(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    description: String,
    blocked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            imageVector = icon,
            contentDescription = description,
            modifier = Modifier.size(18.dp),
            tint = if (blocked) VerdictColors.blocked else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        // Switch on means "blocked", matching the icon turning red.
        Switch(checked = blocked, onCheckedChange = onChange)
    }
}

@Composable
private fun AppIcon(drawable: android.graphics.drawable.Drawable?) {
    val painter = remember(drawable) {
        drawable?.let { runCatching { BitmapPainter(it.toBitmap(96, 96).asImageBitmap()) }.getOrNull() }
    }
    if (painter != null) {
        androidx.compose.foundation.Image(
            painter = painter,
            contentDescription = null,
            modifier = Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)),
        )
    } else {
        Box(
            Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Filled.Android, contentDescription = null, Modifier.size(24.dp))
        }
    }
}
