package com.qopsec.firewall.ui

import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qopsec.firewall.data.AppPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope

private data class AppItem(val label: String, val pkg: String)

@Composable
fun PerAppScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val policy = remember { AppPolicy.get(context) }
    val adExempt by policy.adBlockExempt.collectAsStateWithLifecycle()
    val fwExcluded by policy.firewallExcluded.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    var apps by remember { mutableStateOf<List<AppItem>?>(null) }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { loadInternetApps(context) }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(modifier = Modifier.fillMaxSize().systemBarsPadding().padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("← Back") }
                Spacer(Modifier.width(4.dp))
                Text("Per-app rules", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "“Exempt ad-block” stops ad/tracker blocking for an app’s connections — but DNS-level " +
                    "blocking is system-wide, so it fully applies only to its direct/IP/encrypted-DNS " +
                    "traffic. “Bypass firewall” removes the app from the VPN entirely (no filtering, " +
                    "capture, or kill switch) and takes effect after you Stop→Start the firewall.",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))

            val list = apps
            if (list == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(list, key = { it.pkg }) { app ->
                        AppRow(
                            app = app,
                            adExempt = app.pkg in adExempt,
                            fwExcluded = app.pkg in fwExcluded,
                            onAdExempt = { scope.launch { policy.setAdBlockExempt(app.pkg, it) } },
                            onFwExcluded = { scope.launch { policy.setFirewallExcluded(app.pkg, it) } },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AppRow(
    app: AppItem,
    adExempt: Boolean,
    fwExcluded: Boolean,
    onAdExempt: (Boolean) -> Unit,
    onFwExcluded: (Boolean) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text(app.label, style = MaterialTheme.typography.bodyLarge)
        Text(app.pkg, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(6.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            SwitchChip("Exempt ad-block", adExempt, onAdExempt, Modifier.weight(1f))
            SwitchChip("Bypass firewall", fwExcluded, onFwExcluded, Modifier.weight(1f))
        }
    }
}

@Composable
private fun SwitchChip(label: String, checked: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = checked, onCheckedChange = onChange)
        Spacer(Modifier.width(8.dp))
        Text(label, style = MaterialTheme.typography.labelMedium)
    }
}

/** Installed apps that request INTERNET (the ones a firewall is relevant to), minus ourselves. */
private fun loadInternetApps(context: Context): List<AppItem> {
    val pm = context.packageManager
    val self = context.packageName
    val pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    return pkgs.asSequence()
        .filter { it.packageName != self }
        .filter { it.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true }
        .map {
            val label = it.applicationInfo?.let { ai -> pm.getApplicationLabel(ai).toString() }
            AppItem(label ?: it.packageName, it.packageName)
        }
        .sortedBy { it.label.lowercase() }
        .toList()
}
