package dev.shadow.firewall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.shadow.firewall.R

/**
 * Global policy, the domain lists, and the escape hatch that clears every rule.
 *
 * The domain lists are plain text areas rather than a managed list UI: people arrive with a
 * blocklist copied from somewhere else, and pasting it should just work.
 */
@Composable
fun SettingsScreen(viewModel: FirewallViewModel, modifier: Modifier = Modifier) {
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val blocklistStatuses by viewModel.blocklistStatuses.collectAsStateWithLifecycle()
    val refreshing by viewModel.blocklistRefreshing.collectAsStateWithLifecycle()
    val entryCount by viewModel.blocklistEntryCount.collectAsStateWithLifecycle()
    var confirmClear by remember { mutableStateOf(false) }

    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SettingsCard(stringResource(R.string.settings_policy)) {
            SettingsSwitch(
                title = stringResource(R.string.setting_block_by_default),
                summary = stringResource(R.string.setting_block_by_default_summary),
                checked = settings.rules.blockByDefault,
                onCheckedChange = viewModel::setBlockByDefault,
            )
            HorizontalDivider()
            SettingsSwitch(
                title = stringResource(R.string.setting_block_encrypted_dns),
                summary = stringResource(R.string.setting_block_encrypted_dns_summary),
                checked = settings.rules.blockEncryptedDns,
                onCheckedChange = viewModel::setBlockEncryptedDns,
            )
            HorizontalDivider()
            SettingsSwitch(
                title = stringResource(R.string.setting_block_ipv6),
                summary = stringResource(R.string.setting_block_ipv6_summary),
                checked = settings.rules.blockIpv6,
                onCheckedChange = viewModel::setBlockIpv6,
            )
            HorizontalDivider()
            SettingsSwitch(
                title = stringResource(R.string.setting_auto_start),
                summary = stringResource(R.string.setting_auto_start_summary),
                checked = settings.autoStartOnBoot,
                onCheckedChange = viewModel::setAutoStartOnBoot,
            )
        }

        BlocklistSection(
            statuses = blocklistStatuses,
            useBlocklists = settings.rules.useBlocklists,
            frequency = settings.updateFrequency,
            unmeteredOnly = settings.updateOnUnmeteredOnly,
            refreshing = refreshing,
            totalEntries = entryCount,
            onUseBlocklists = viewModel::setUseBlocklists,
            onToggleList = viewModel::setBlocklistEnabled,
            onFrequency = viewModel::setUpdateFrequency,
            onUnmeteredOnly = viewModel::setUpdateOnUnmeteredOnly,
            onUpdateNow = viewModel::updateBlocklistsNow,
        )

        DomainListCard(
            title = stringResource(R.string.settings_blocked_domains),
            summary = stringResource(R.string.settings_blocked_domains_summary),
            domains = settings.rules.blockedDomains,
            onSave = viewModel::setBlockedDomains,
        )

        DomainListCard(
            title = stringResource(R.string.settings_allowed_domains),
            summary = stringResource(R.string.settings_allowed_domains_summary),
            domains = settings.rules.allowedDomains,
            onSave = viewModel::setAllowedDomains,
        )

        SettingsCard(stringResource(R.string.settings_maintenance)) {
            Text(
                text = stringResource(R.string.settings_reset_summary),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { confirmClear = true }) {
                Text(stringResource(R.string.action_reset_rules))
            }
        }

        Text(
            text = stringResource(R.string.settings_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.action_reset_rules)) },
            text = { Text(stringResource(R.string.reset_confirm)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.clearAllRules()
                    confirmClear = false
                }) { Text(stringResource(R.string.action_reset)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = {
                Text(title, style = MaterialTheme.typography.titleMedium)
                content()
            },
        )
    }
}

@Composable
private fun SettingsSwitch(
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

@Composable
private fun DomainListCard(
    title: String,
    summary: String,
    domains: Set<String>,
    onSave: (String) -> Unit,
) {
    val stored = remember(domains) { domains.sorted().joinToString("\n") }
    var text by remember(stored) { mutableStateOf(stored) }
    // Reset the editor when the stored list changes underneath it.
    LaunchedEffect(stored) { text = stored }

    SettingsCard(title) {
        Text(
            summary,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 10,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
            placeholder = { Text(stringResource(R.string.domain_placeholder)) },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { onSave(text) }, enabled = text != stored) {
                Text(stringResource(R.string.action_save))
            }
            if (text != stored) {
                TextButton(onClick = { text = stored }) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
        }
        Text(
            text = stringResource(R.string.domain_count, domains.size),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
