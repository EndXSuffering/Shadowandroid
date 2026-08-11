package dev.shadow.firewall.ui

import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
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
                    onToggle = { network, blocked ->
                        viewModel.toggleBlock(item.app.uid, network, blocked)
                    },
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
    onToggle: (NetworkType, Boolean) -> Unit,
) {
    ElevatedCard(Modifier.fillMaxWidth()) {
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
