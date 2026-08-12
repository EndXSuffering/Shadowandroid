package dev.shadow.firewall.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.shadow.firewall.R
import dev.shadow.firewall.core.BlockReason
import dev.shadow.firewall.core.ConnectionEvent
import dev.shadow.firewall.core.IpProto
import dev.shadow.firewall.core.UidNames
import dev.shadow.firewall.core.Verdict
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The live traffic view: every connection the tunnel has seen, newest first, with what was
 * done about it. Tapping a row offers to block the app or the hostname behind it.
 */
@Composable
fun TrafficScreen(
    viewModel: FirewallViewModel,
    vpnRunning: Boolean,
    modifier: Modifier = Modifier,
) {
    val events by viewModel.traffic.collectAsStateWithLifecycle()
    val filter by viewModel.trafficFilter.collectAsStateWithLifecycle()
    var selected by remember { mutableStateOf<ConnectionEvent?>(null) }

    Column(modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            for (option in TrafficFilter.entries) {
                FilterChip(
                    selected = filter == option,
                    onClick = { viewModel.setTrafficFilter(option) },
                    label = {
                        Text(
                            stringResource(
                                when (option) {
                                    TrafficFilter.ALL -> R.string.filter_all
                                    TrafficFilter.BLOCKED -> R.string.filter_blocked
                                    TrafficFilter.ALLOWED -> R.string.filter_allowed
                                },
                            ),
                        )
                    },
                )
            }
            Spacer(Modifier.weight(1f))
            TextButton(onClick = viewModel::clearTraffic) {
                Text(stringResource(R.string.action_clear))
            }
        }

        if (events.isEmpty()) {
            EmptyTraffic(vpnRunning)
            return@Column
        }

        LazyColumn(
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(events, key = { it.id }) { event ->
                TrafficRow(event, onClick = { selected = event })
            }
        }
    }

    selected?.let { event ->
        ConnectionActions(
            event = event,
            onDismiss = { selected = null },
            onBlockApp = {
                viewModel.blockEverywhere(event.uid)
                selected = null
            },
            onBlockDomain = {
                event.hostname?.let(viewModel::blockDomain)
                selected = null
            },
        )
    }
}

@Composable
private fun EmptyTraffic(vpnRunning: Boolean) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(
            text = stringResource(
                if (vpnRunning) R.string.traffic_empty_running else R.string.traffic_empty_stopped,
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(32.dp),
        )
    }
}

@Composable
private fun TrafficRow(event: ConnectionEvent, onClick: () -> Unit) {
    val blocked = event.verdict == Verdict.BLOCK
    // stringResource is composable, so the reason has to be resolved before buildString.
    val reasonText = when {
        !blocked -> null
        // For a subscribed list, naming the list is more use than "blocked by a list".
        event.reason == BlockReason.SUBSCRIBED_LIST && event.ruleSource != null -> event.ruleSource
        else -> stringResource(reasonLabel(event.reason))
    }
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(if (blocked) VerdictColors.blocked else VerdictColors.allowed),
            )
            Spacer(Modifier.width(12.dp))

            Column(Modifier.weight(1f)) {
                Text(
                    text = event.appLabel ?: stringResource(R.string.unknown_app, event.uid),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (event.packageName == null) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "${event.displayTarget}:${event.destinationPort}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = buildString {
                        append(IpProto.name(event.protocol))
                        append(" · ")
                        append(formatTime(event.startedAtMillis))
                        if (reasonText != null) {
                            append(" · ")
                            append(reasonText)
                        } else if (event.bytesIn > 0 || event.bytesOut > 0) {
                            append(" · ↑")
                            append(formatBytes(event.bytesOut))
                            append(" ↓")
                            append(formatBytes(event.bytesIn))
                        }
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            if (blocked) {
                Icon(
                    Icons.Filled.Block,
                    contentDescription = stringResource(R.string.filter_blocked),
                    tint = VerdictColors.blocked,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}

@Composable
private fun ConnectionActions(
    event: ConnectionEvent,
    onDismiss: () -> Unit,
    onBlockApp: () -> Unit,
    onBlockDomain: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(event.appLabel ?: stringResource(R.string.unknown_app, event.uid)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                DetailLine(stringResource(R.string.detail_destination), "${event.displayTarget}:${event.destinationPort}")
                DetailLine(stringResource(R.string.detail_address), event.destinationAddress)
                DetailLine(stringResource(R.string.detail_protocol), IpProto.name(event.protocol))
                DetailLine(stringResource(R.string.detail_package), event.packageName ?: "—")
                DetailLine(
                    stringResource(R.string.detail_verdict),
                    if (event.verdict == Verdict.BLOCK) {
                        event.ruleSource ?: stringResource(reasonLabel(event.reason))
                    } else {
                        stringResource(R.string.filter_allowed)
                    },
                )
                DetailLine(
                    stringResource(R.string.detail_transferred),
                    "↑ ${formatBytes(event.bytesOut)}   ↓ ${formatBytes(event.bytesIn)}",
                )
                DetailLine(stringResource(R.string.detail_uid), event.uid.toString())
                UidNames.unattributedExplanation(event.uid)?.let { explanation ->
                    Text(
                        text = explanation,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onBlockApp, enabled = event.uid >= 0) {
                Text(stringResource(R.string.action_block_app))
            }
        },
        dismissButton = {
            Row {
                if (event.hostname != null) {
                    TextButton(onClick = onBlockDomain) {
                        Text(stringResource(R.string.action_block_domain))
                    }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_close)) }
            }
        },
    )
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(96.dp),
        )
        Text(text = value, style = MaterialTheme.typography.bodySmall)
    }
}

private fun reasonLabel(reason: BlockReason): Int = when (reason) {
    BlockReason.APP_RULE -> R.string.reason_app_rule
    BlockReason.DEFAULT_POLICY -> R.string.reason_default_policy
    BlockReason.DOMAIN_BLOCKLIST -> R.string.reason_domain
    BlockReason.SUBSCRIBED_LIST -> R.string.reason_subscribed_list
    BlockReason.IPV6_DISABLED -> R.string.reason_ipv6
    BlockReason.NONE -> R.string.filter_allowed
}

private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

private fun formatTime(millis: Long): String = timeFormat.format(Date(millis))

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "${bytes}B"
    bytes < 1024 * 1024 -> String.format(Locale.US, "%.1fkB", bytes / 1024.0)
    bytes < 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1fMB", bytes / (1024.0 * 1024))
    else -> String.format(Locale.US, "%.2fGB", bytes / (1024.0 * 1024 * 1024))
}
