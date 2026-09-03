package dev.shadow.firewall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.shadow.firewall.R
import dev.shadow.firewall.rules.BlocklistCategory
import dev.shadow.firewall.rules.BlocklistStatus
import dev.shadow.firewall.rules.TrackerProtection
import dev.shadow.firewall.rules.UpdateFrequency
import java.text.DateFormat
import java.util.Date
import java.util.Locale

/**
 * The subscribed-lists section of the settings screen: what is on, how big it is, when it
 * last updated, and whether the last update failed.
 */
@Composable
fun BlocklistSection(
    statuses: List<BlocklistStatus>,
    useBlocklists: Boolean,
    frequency: UpdateFrequency,
    unmeteredOnly: Boolean,
    refreshing: Boolean,
    totalEntries: Int,
    trackerProtection: TrackerProtection,
    onTrackerProtection: (TrackerProtection) -> Unit,
    onUseBlocklists: (Boolean) -> Unit,
    onToggleList: (String, Boolean) -> Unit,
    onFrequency: (UpdateFrequency) -> Unit,
    onUnmeteredOnly: (Boolean) -> Unit,
    onUpdateNow: () -> Unit,
) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.settings_blocklists), style = MaterialTheme.typography.titleMedium)

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.setting_use_blocklists),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        text = if (totalEntries > 0) {
                            stringResource(R.string.blocklist_total, formatCount(totalEntries))
                        } else {
                            stringResource(R.string.blocklist_total_empty)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Switch(checked = useBlocklists, onCheckedChange = onUseBlocklists)
            }

            HorizontalDivider()

            Text(stringResource(R.string.tracker_level), style = MaterialTheme.typography.labelLarge)
            Text(
                stringResource(R.string.tracker_level_summary),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (level in TrackerProtection.entries) {
                    FilterChip(
                        selected = trackerProtection == level,
                        onClick = { onTrackerProtection(level) },
                        enabled = useBlocklists,
                        label = { Text(stringResource(trackerLevelLabel(level))) },
                    )
                }
            }
            Text(
                text = stringResource(trackerLevelDetail(trackerProtection)),
                style = MaterialTheme.typography.bodySmall,
                color = if (trackerProtection == TrackerProtection.STRICT) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )

            HorizontalDivider()

            for (category in BlocklistCategory.entries) {
                val inCategory = statuses.filter { it.source.category == category }
                if (inCategory.isEmpty()) continue
                Text(
                    text = stringResource(
                        when (category) {
                            BlocklistCategory.ADS -> R.string.blocklist_category_ads
                            BlocklistCategory.TRACKING -> R.string.blocklist_category_tracking
                            BlocklistCategory.MALWARE -> R.string.blocklist_category_malware
                        },
                    ),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
                for (status in inCategory) {
                    BlocklistRow(
                        status = status,
                        enabled = useBlocklists,
                        onToggle = { onToggleList(status.source.id, it) },
                    )
                }
            }

            HorizontalDivider()

            Text(stringResource(R.string.blocklist_update_every), style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (option in UpdateFrequency.entries) {
                    FilterChip(
                        selected = frequency == option,
                        onClick = { onFrequency(option) },
                        label = { Text(stringResource(frequencyLabel(option))) },
                    )
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.setting_unmetered_only),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        stringResource(R.string.setting_unmetered_only_summary),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Switch(checked = unmeteredOnly, onCheckedChange = onUnmeteredOnly)
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = onUpdateNow, enabled = !refreshing) {
                    Text(stringResource(R.string.action_update_now))
                }
                if (refreshing) {
                    Spacer(Modifier.width(12.dp))
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                }
            }

            Text(
                stringResource(R.string.blocklist_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun BlocklistRow(
    status: BlocklistStatus,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(
                text = status.source.title,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = status.source.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (status.hasData) {
                    Text(
                        text = stringResource(
                            R.string.blocklist_entry_summary,
                            formatCount(status.entryCount),
                            formatUpdated(status.updatedAtMillis),
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else if (status.enabled) {
                    Text(
                        stringResource(R.string.blocklist_not_downloaded),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (status.source.isHeavy) {
                    AssistChip(
                        onClick = {},
                        label = { Text(stringResource(R.string.blocklist_heavy)) },
                    )
                }
            }
            status.lastError?.let { error ->
                Text(
                    text = stringResource(R.string.blocklist_last_error, error),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = status.enabled, onCheckedChange = onToggle, enabled = enabled)
    }
}

private fun trackerLevelLabel(level: TrackerProtection): Int = when (level) {
    TrackerProtection.OFF -> R.string.tracker_off
    TrackerProtection.BALANCED -> R.string.tracker_balanced
    TrackerProtection.STRICT -> R.string.tracker_strict
}

private fun trackerLevelDetail(level: TrackerProtection): Int = when (level) {
    TrackerProtection.OFF -> R.string.tracker_off_detail
    TrackerProtection.BALANCED -> R.string.tracker_balanced_detail
    TrackerProtection.STRICT -> R.string.tracker_strict_detail
}

private fun frequencyLabel(frequency: UpdateFrequency): Int = when (frequency) {
    UpdateFrequency.EVERY_6_HOURS -> R.string.frequency_6_hours
    UpdateFrequency.DAILY -> R.string.frequency_daily
    UpdateFrequency.WEEKLY -> R.string.frequency_weekly
    UpdateFrequency.MANUAL -> R.string.frequency_manual
}

private fun formatCount(count: Int): String = when {
    count >= 1_000_000 -> String.format(Locale.getDefault(), "%.1fM", count / 1_000_000.0)
    count >= 1_000 -> String.format(Locale.getDefault(), "%.0fk", count / 1_000.0)
    else -> count.toString()
}

private fun formatUpdated(millis: Long): String {
    if (millis == 0L) return "—"
    val age = System.currentTimeMillis() - millis
    return when {
        age < 60_000 -> "just now"
        age < 3_600_000 -> "${age / 60_000}m ago"
        age < 86_400_000 -> "${age / 3_600_000}h ago"
        age < 7 * 86_400_000L -> "${age / 86_400_000}d ago"
        else -> DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(millis))
    }
}
