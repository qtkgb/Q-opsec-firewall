package com.qopsec.firewall.ui

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qopsec.firewall.data.BiometricAuth
import com.qopsec.firewall.data.BlockList
import com.qopsec.firewall.data.BlocklistManager
import com.qopsec.firewall.data.LockStore
import com.qopsec.firewall.data.LogExporter
import com.qopsec.firewall.data.Settings
import com.qopsec.firewall.data.ThemeMode
import com.qopsec.firewall.data.UpdateCheckWorker
import com.qopsec.firewall.data.UpdateManager
import com.qopsec.firewall.data.UpdateState
import com.qopsec.firewall.data.UserDomains
import com.qopsec.firewall.vpn.NativeBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SettingsScreen(onBack: () -> Unit, onPerApp: () -> Unit) {
    val context = LocalContext.current
    val lock = remember { LockStore.get(context) }
    val settings = remember { Settings.get(context) }
    val lockEnabled by lock.enabled.collectAsStateWithLifecycle()
    val biometricEnabled by lock.biometricEnabled.collectAsStateWithLifecycle()
    val themeMode by settings.themeMode.collectAsStateWithLifecycle()
    val askMode by settings.askMode.collectAsStateWithLifecycle()
    val bootLock by settings.bootLock.collectAsStateWithLifecycle()
    val adBlock by settings.adBlock.collectAsStateWithLifecycle()
    val blockEncDns by settings.blockEncryptedDns.collectAsStateWithLifecycle()
    val dnsResolver by settings.dnsResolver.collectAsStateWithLifecycle()
    val forwardIpv6 by settings.forwardIpv6.collectAsStateWithLifecycle()
    val blockMgr = remember { BlocklistManager.get(context) }
    val sourceState by blockMgr.state.collectAsStateWithLifecycle()
    val userDomains = remember { UserDomains.get(context) }
    val customBlock by userDomains.block.collectAsStateWithLifecycle()
    val allowList by userDomains.allow.collectAsStateWithLifecycle()
    // Re-read the merged total whenever any contributing list changes so the count recomposes.
    val blockCount = remember(sourceState, customBlock, allowList) { BlockList.get(context).size }
    val updateMgr = remember { UpdateManager.get(context) }
    val autoUpdate by settings.autoUpdateCheck.collectAsStateWithLifecycle()
    val updateAvailable by updateMgr.available.collectAsStateWithLifecycle()
    val updateState by updateMgr.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var showSet by remember { mutableStateOf(false) }
    var showDisable by remember { mutableStateOf(false) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("← Back") }
                Spacer(Modifier.width(4.dp))
                Text(
                    text = "Settings",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                )
            }
            Spacer(Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("App lock", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        text = "Require a passcode to open the app",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = lockEnabled,
                    onCheckedChange = { if (it) showSet = true else showDisable = true },
                )
            }
            if (lockEnabled && BiometricAuth.available(context)) {
                Spacer(Modifier.height(12.dp))
                ToggleRow(
                    title = "Unlock with biometrics",
                    subtitle = "Use fingerprint or face; passcode stays as fallback",
                    checked = biometricEnabled,
                    onChange = { lock.setBiometric(it) },
                )
            }

            Spacer(Modifier.height(22.dp))
            ToggleRow(
                title = "Block ads & trackers",
                subtitle = "DNS-level blocking · $blockCount domains loaded",
                checked = adBlock,
                onChange = { settings.setAdBlock(it) },
            )
            if (adBlock) {
                Spacer(Modifier.height(10.dp))
                blockMgr.sources.forEach { s ->
                    val info = sourceState[s.id]
                    val sub = when {
                        info?.enabled != true -> "Not subscribed"
                        info.count > 0 -> "${info.count} domains"
                        else -> "Updating…"
                    }
                    ToggleRow(
                        title = s.name,
                        subtitle = sub,
                        checked = info?.enabled == true,
                        onChange = { blockMgr.setEnabled(s.id, it) },
                    )
                    Spacer(Modifier.height(8.dp))
                }
                OutlinedButton(onClick = { blockMgr.updateNow() }) { Text("Update now") }

                Spacer(Modifier.height(18.dp))
                DomainListEditor(
                    title = "Custom blocked domains",
                    subtitle = "Block these in addition to the lists above",
                    placeholder = "ads.example.com",
                    domains = customBlock,
                    onAdd = { userDomains.addBlock(it) },
                    onRemove = { userDomains.removeBlock(it) },
                )

                Spacer(Modifier.height(18.dp))
                DomainListEditor(
                    title = "Allowed (exceptions)",
                    subtitle = "Never block these, even if they're on a list",
                    placeholder = "tracker.example.com",
                    domains = allowList,
                    onAdd = { userDomains.addAllow(it) },
                    onRemove = { userDomains.removeAllow(it) },
                )

                Spacer(Modifier.height(18.dp))
                ToggleRow(
                    title = "Block encrypted DNS (DoH/DoT)",
                    subtitle = "Force DNS back to the sinkhole; may break apps using a fixed resolver",
                    checked = blockEncDns,
                    onChange = { settings.setBlockEncryptedDns(it) },
                )
            }

            Spacer(Modifier.height(16.dp))
            ToggleRow(
                title = "Ask for new apps",
                subtitle = "Hold an unknown app's first connection and prompt",
                checked = askMode,
                onChange = { settings.setAskMode(it) },
            )
            Spacer(Modifier.height(16.dp))
            ToggleRow(
                title = "Boot-lock",
                subtitle = "On reboot, start blocking until you unlock",
                checked = bootLock,
                onChange = { settings.setBootLock(it) },
            )

            Spacer(Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth().clickable {
                    // No reliable per-app deep link across OEMs; open the VPN settings list, where
                    // the user taps our app's gear → "Always-on VPN" + "Block connections without VPN".
                    runCatching {
                        context.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
                    }
                },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Always-on VPN", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        text = "OS-level: auto-start on boot and block all traffic when the firewall " +
                            "is off. Enable Always-on + “Block connections without VPN” for this app.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text("↗", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth().clickable { onPerApp() },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Per-app rules", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        text = "Exempt apps from ad-block, or bypass the firewall entirely",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text("›", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(22.dp))
            DnsResolverSection(
                current = dnsResolver,
                onSet = { settings.setDnsResolver(it) },
            )

            Spacer(Modifier.height(16.dp))
            ToggleRow(
                title = "Forward IPv6 (experimental)",
                subtitle = "Off = IPv4 only (recommended). Some networks advertise IPv6 but can't " +
                    "route it, which breaks apps like WhatsApp. Enable only if your network has " +
                    "working IPv6.",
                checked = forwardIpv6,
                onChange = { settings.setForwardIpv6(it) },
            )

            Spacer(Modifier.height(22.dp))
            ToggleRow(
                title = "Check for updates daily",
                subtitle = "Installed v${updateMgr.currentVersion()} · checks GitHub releases",
                checked = autoUpdate,
                onChange = {
                    settings.setAutoUpdateCheck(it)
                    UpdateCheckWorker.schedule(context, it)
                },
            )
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    enabled = updateState !is UpdateState.Checking &&
                        updateState !is UpdateState.Downloading,
                    onClick = { scope.launch { updateMgr.checkForUpdate() } },
                ) { Text("Check now") }
                Spacer(Modifier.width(12.dp))
                val statusText = when (val s = updateState) {
                    is UpdateState.Checking -> "Checking…"
                    is UpdateState.UpToDate -> "Up to date"
                    is UpdateState.Downloading -> "Downloading ${s.percent}%"
                    is UpdateState.Error -> s.message
                    is UpdateState.Idle -> ""
                }
                if (statusText.isNotEmpty()) {
                    Text(
                        statusText,
                        style = MaterialTheme.typography.labelMedium,
                        color = if (updateState is UpdateState.Error)
                            MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            updateAvailable?.let { info ->
                Spacer(Modifier.height(12.dp))
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .padding(14.dp),
                ) {
                    Text(
                        "Update available — v${info.version}",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    if (info.notes.isNotBlank()) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            info.notes.trim().take(300),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Button(
                        enabled = updateState !is UpdateState.Downloading,
                        onClick = { scope.launch { updateMgr.downloadAndInstall(info) } },
                    ) {
                        Text(
                            if (updateState is UpdateState.Downloading)
                                "Downloading ${(updateState as UpdateState.Downloading).percent}%"
                            else "Download & install",
                        )
                    }
                }
            }

            Spacer(Modifier.height(22.dp))
            Text("Theme", style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ThemeChip("System", themeMode == ThemeMode.SYSTEM) { settings.setThemeMode(ThemeMode.SYSTEM) }
                ThemeChip("Light", themeMode == ThemeMode.LIGHT) { settings.setThemeMode(ThemeMode.LIGHT) }
                ThemeChip("Dark", themeMode == ThemeMode.DARK) { settings.setThemeMode(ThemeMode.DARK) }
            }

            // TEMPORARY DIAGNOSTIC (stop-hang investigation): capture + share this app's start/stop
            // log straight from the phone (no adb). Remove with the rest of the instrumentation.
            Spacer(Modifier.height(22.dp))
            Text("Diagnostics", style = MaterialTheme.typography.bodyLarge)
            Text(
                text = "Capture the firewall start/stop log and share it (for debugging the stop issue). " +
                    "Reproduce first: Start → use the phone a bit → Stop, then save the log.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            var savingLog by remember { mutableStateOf(false) }
            OutlinedButton(
                enabled = !savingLog,
                onClick = {
                    savingLog = true
                    scope.launch {
                        val f = withContext(Dispatchers.IO) { LogExporter.capture(context) }
                        savingLog = false
                        LogExporter.share(context, f)
                    }
                },
            ) { Text(if (savingLog) "Saving…" else "Save & share log") }

            Spacer(Modifier.height(28.dp))
            Text(
                text = "core: " + remember { NativeBridge.status() },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    if (showSet) {
        SetPasscodeDialog(
            onDismiss = { showSet = false },
            onSet = { lock.setPasscode(it); showSet = false },
        )
    }
    if (showDisable) {
        VerifyPasscodeDialog(
            title = "Turn off app lock",
            verify = lock::verify,
            onDismiss = { showDisable = false },
            onVerified = { lock.clear(); showDisable = false },
        )
    }
}

@Composable
private fun SetPasscodeDialog(onDismiss: () -> Unit, onSet: (String) -> Unit) {
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val valid = pin.length >= 4 && pin == confirm
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set passcode") },
        text = {
            Column {
                Text("At least 4 characters. Stored only as a salted hash.")
                Spacer(Modifier.height(10.dp))
                PasscodeField("New passcode", pin) { pin = it }
                Spacer(Modifier.height(8.dp))
                PasscodeField("Confirm", confirm) { confirm = it }
                if (confirm.isNotEmpty() && pin != confirm) {
                    Text(
                        "Passcodes don't match",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = { TextButton(enabled = valid, onClick = { onSet(pin) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun VerifyPasscodeDialog(
    title: String,
    verify: (String) -> Boolean,
    onDismiss: () -> Unit,
    onVerified: () -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                PasscodeField("Current passcode", pin) { pin = it; error = false }
                if (error) {
                    Text(
                        "Incorrect passcode",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = pin.isNotEmpty(),
                onClick = { if (verify(pin)) onVerified() else error = true },
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ToggleRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

private data class DnsPreset(val name: String, val ip: String)

private val DNS_PRESETS = listOf(
    DnsPreset("Cloudflare", "1.1.1.1"),
    DnsPreset("Google", "8.8.8.8"),
    DnsPreset("Quad9", "9.9.9.9"),
)

/** True for a well-formed IPv4 literal (four 0–255 octets). */
private fun isValidIpv4(s: String): Boolean {
    val parts = s.trim().split(".")
    return parts.size == 4 && parts.all { p -> p.toIntOrNull()?.let { it in 0..255 } == true && (p.length == 1 || p.first() != '0') }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DnsResolverSection(current: String, onSet: (String) -> Unit) {
    var custom by remember { mutableStateOf("") }
    val isPreset = DNS_PRESETS.any { it.ip == current }
    Column(modifier = Modifier.fillMaxWidth()) {
        Text("DNS resolver", style = MaterialTheme.typography.bodyLarge)
        Text(
            text = "Upstream resolver for non-blocked queries (IPv4). Restart the firewall to apply.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DNS_PRESETS.forEach { p ->
                ThemeChip("${p.name} (${p.ip})", current == p.ip) { onSet(p.ip) }
            }
        }
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = custom,
                onValueChange = { custom = it },
                placeholder = { Text(if (isPreset) "Custom IPv4…" else current) },
                singleLine = true,
                isError = custom.isNotBlank() && !isValidIpv4(custom),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(
                enabled = isValidIpv4(custom),
                onClick = { onSet(custom.trim()); custom = "" },
            ) { Text("Set") }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = "Current: $current",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun DomainListEditor(
    title: String,
    subtitle: String,
    placeholder: String,
    domains: Set<String>,
    onAdd: (String) -> Unit,
    onRemove: (String) -> Unit,
) {
    var text by remember { mutableStateOf("") }
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(title, style = MaterialTheme.typography.bodyLarge)
        Text(
            text = subtitle,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                placeholder = { Text(placeholder) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(
                enabled = text.isNotBlank(),
                onClick = { onAdd(text.trim()); text = "" },
            ) { Text("Add") }
        }
        if (domains.isEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text(
                text = "None yet",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            domains.sorted().forEach { d ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(d, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    TextButton(onClick = { onRemove(d) }) { Text("Remove") }
                }
            }
        }
    }
}

@Composable
private fun ThemeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    if (selected) {
        Button(onClick = onClick) { Text(label) }
    } else {
        OutlinedButton(onClick = onClick) { Text(label) }
    }
}

@Composable
private fun PasscodeField(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
}
