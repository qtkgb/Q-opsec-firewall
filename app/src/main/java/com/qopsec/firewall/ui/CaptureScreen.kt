package com.qopsec.firewall.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qopsec.firewall.R
import com.qopsec.firewall.data.BlockList
import com.qopsec.firewall.data.ConnLog
import com.qopsec.firewall.data.Rule
import com.qopsec.firewall.data.RuleRepository
import com.qopsec.firewall.data.Settings
import com.qopsec.firewall.data.Snapshot
import com.qopsec.firewall.data.TrashPurgeWorker
import com.qopsec.firewall.vpn.CaptureLog
import com.qopsec.firewall.vpn.ConnectionEvent
import com.qopsec.firewall.vpn.L4
import com.qopsec.firewall.vpn.NativeBridge

@Composable
fun CaptureScreen(
    onStart: () -> Unit,
    onStop: () -> Unit,
    onKill: (Boolean) -> Unit,
    onSettings: () -> Unit,
) {
    val context = LocalContext.current
    val repo = remember { RuleRepository.get(context) }

    val running by CaptureLog.running.collectAsStateWithLifecycle()
    val killed by CaptureLog.killed.collectAsStateWithLifecycle()
    val undoCount by repo.undoCount.collectAsStateWithLifecycle(initialValue = 0)
    var tab by remember { mutableStateOf(0) }
    var searchOpen by remember { mutableStateOf(false) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(modifier = Modifier.fillMaxSize().systemBarsPadding().padding(16.dp)) {

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Q opsec firewall",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = onSettings) { Text("Settings") }
            }
            Text(
                text = when {
                    !running -> "Stopped"
                    killed -> "Kill switch ON — all traffic blocked"
                    NativeBridge.available -> "Filtering — internet active"
                    else -> "Capturing — traffic paused (Phase 1a)"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = if (killed) LocalStatusPalette.current.blocked else MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(onClick = { if (running) onStop() else onStart() }) {
                    Text(if (running) "Stop" else "Start")
                }
                OutlinedButton(onClick = { repo.clearConn() }) { Text("Clear") }
                OutlinedButton(onClick = { repo.undoLast() }, enabled = undoCount > 0) { Text("Undo") }
                Spacer(modifier = Modifier.weight(1f))
                KillToggle(killed = killed, enabled = running, onToggle = onKill)
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                TabRow(selectedTabIndex = tab, modifier = Modifier.weight(1f)) {
                    val tabBlue = MaterialTheme.colorScheme.primary
                    Tab(selected = tab == 0, onClick = { tab = 0 }, icon = {
                        Icon(painterResource(R.drawable.ic_tab_connections), contentDescription = "Connections", tint = tabBlue)
                    })
                    Tab(selected = tab == 1, onClick = { tab = 1 }, icon = {
                        Icon(painterResource(R.drawable.ic_tab_rules), contentDescription = "Rules", tint = tabBlue)
                    })
                    Tab(selected = tab == 2, onClick = { tab = 2 }, icon = {
                        Icon(painterResource(R.drawable.ic_tab_trash), contentDescription = "Trash", tint = tabBlue)
                    })
                }
                // Search toggle sits next to the tabs; only Connections is searchable. Tap to
                // reveal the search/filter panel, tap again (or ✕) to give the list full height.
                if (tab == 0) {
                    IconButton(onClick = { searchOpen = !searchOpen }) {
                        Icon(
                            painterResource(if (searchOpen) R.drawable.ic_close else R.drawable.ic_search),
                            contentDescription = if (searchOpen) "Close search" else "Search",
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }

            // weight(1f) bounds the tab content to the leftover height so its LazyColumn scrolls.
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                when (tab) {
                    0 -> ConnectionsTab(repo, searchOpen)
                    1 -> RulesTab(repo)
                    else -> TrashTab(repo)
                }
            }
        }
    }
}

/**
 * Compact kill-switch toggle that lives in the action row next to Undo.
 * Inactive = grey pill + grey dot; active = red pill + white dot. The word "KILL"
 * sits inside the pill (no separate label). Disabled (firewall stopped) dims it.
 */
@Composable
private fun KillToggle(killed: Boolean, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    val blocked = LocalStatusPalette.current.blocked
    val bg = if (killed) blocked else MaterialTheme.colorScheme.surfaceVariant
    val fg = if (killed) Color.White else MaterialTheme.colorScheme.onSurfaceVariant
    val alpha = if (enabled) 1f else 0.4f
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(bg.copy(alpha = alpha))
            .clickable(enabled = enabled) { onToggle(!killed) }
            .padding(horizontal = 12.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(
            modifier = Modifier
                .size(12.dp)
                .clip(CircleShape)
                .background((if (killed) Color.White else fg).copy(alpha = alpha)),
        )
        Text(
            "KILL",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            color = fg.copy(alpha = alpha),
        )
    }
}

// --- Connections: searchable, filterable, grouped by app ---

private data class AppInfo(
    val uid: Int,
    val label: String?,
    val packageName: String?,
    val events: List<ConnectionEvent>,
)

private class HostTarget(val app: AppInfo, val ev: ConnectionEvent)

/** Per-flow annotation precomputed once so filtering + rows don't re-run the matcher. */
private data class ConnAnno(val verdict: Int, val isAd: Boolean)

private enum class ConnFilter(val label: String) {
    All("All"), Allowed("Allowed"), Blocked("Blocked"), Ads("Ads & trackers")
}

/** Second, independent filter dimension: protocol or a common destination port. */
private enum class ConnKind(val label: String) {
    Any("Any"), TCP("TCP"), UDP("UDP"), DNS(":53"), HTTPS(":443"), HTTP(":80")
}

private enum class ConnSort(val label: String) { Recent("Recent"), Name("Name"), Busiest("Busiest") }

@Composable
private fun ConnectionsTab(repo: RuleRepository, searchOpen: Boolean) {
    val context = LocalContext.current
    val settings = remember { Settings.get(context) }
    val blockList = remember { BlockList.get(context) }

    // Durable history (survives restarts); updates live as new flows are recorded.
    val log by repo.connLog.collectAsStateWithLifecycle(initialValue = emptyList<ConnLog>())
    val events = remember(log) { log.map { it.toEvent() } }
    // Collected so badges recompute when rules change: each row shows the verdict the CURRENT
    // rules would give it, not the verdict from when it was first seen.
    val rules by repo.allRules.collectAsStateWithLifecycle(initialValue = emptyList<Rule>())
    val adBlock by settings.adBlock.collectAsStateWithLifecycle()

    val expanded = remember { mutableStateMapOf<Int, Boolean>() }
    var hostDialog by remember { mutableStateOf<HostTarget?>(null) }
    var query by remember { mutableStateOf("") }
    var filter by remember {
        mutableStateOf(runCatching { ConnFilter.valueOf(settings.connFilter()) }.getOrDefault(ConnFilter.All))
    }
    var kind by remember {
        mutableStateOf(runCatching { ConnKind.valueOf(settings.connKind()) }.getOrDefault(ConnKind.Any))
    }
    var sort by remember {
        mutableStateOf(runCatching { ConnSort.valueOf(settings.connSort()) }.getOrDefault(ConnSort.Recent))
    }
    var confirmBlockAll by remember { mutableStateOf(false) }

    // Precompute the rules-only verdict + the ad/tracker status (DNS blocklist) per flow, once,
    // so neither the filter nor the rows re-run the matcher on every keystroke/recompose.
    val annos = remember(events, rules, adBlock) {
        events.associateWith { ev ->
            val verdict = repo.decideIn(
                rules, ev.uid, ev.packageName, protoNum(ev.protocol), ev.dstIp, ev.host, ev.dstPort,
            ).action
            val isAd = adBlock && ev.host?.let { blockList.isBlocked(it) } == true
            ConnAnno(verdict, isAd)
        }
    }

    val filtering = query.isNotBlank() || filter != ConnFilter.All || kind != ConnKind.Any

    // Groups are always built from ALL of an app's events (so the per-app status pill stays
    // truthful); `visible` is the filtered subset shown when expanded. Apps with no visible
    // child are dropped. A text hit on the app name shows all its (filter-passing) children.
    val groups = remember(events, annos, query, filter, kind, sort) {
        val q = query.trim().lowercase()
        events.groupBy { it.uid }
            .map { (uid, evs) ->
                val label = evs.firstNotNullOfOrNull { it.appLabel }
                val pkg = evs.firstNotNullOfOrNull { it.packageName }
                val appHit = q.isNotEmpty() &&
                    ((label?.lowercase()?.contains(q) == true) || (pkg?.lowercase()?.contains(q) == true))
                val visible = evs.filter { ev ->
                    val anno = annos[ev] ?: ConnAnno(Rule.ACTION_ALLOW, false)
                    filterPass(anno, filter) && kindPass(ev, kind) &&
                        (q.isEmpty() || appHit || matchesText(ev, q))
                }
                AppInfo(uid, label, pkg, evs) to visible
            }
            .filter { (_, visible) -> visible.isNotEmpty() }
            .let { list ->
                when (sort) {
                    ConnSort.Name -> list.sortedBy { (app, _) -> (app.label ?: "~").lowercase() }
                    ConnSort.Busiest -> list.sortedByDescending { (app, _) -> app.events.size }
                    ConnSort.Recent -> list.sortedByDescending { (app, _) -> app.events.maxOf { it.timeMs } }
                }
            }
    }

    val shown = groups.sumOf { it.second.size }
    // Deduped destinations behind the visible rows — one deny rule each for "Block all shown".
    val targets = remember(groups) {
        groups.flatMap { (app, visible) ->
            visible.map { ev -> RuleRepository.DestTarget(app.uid, app.packageName, app.label, ev.host, ev.dstIp) }
        }.distinctBy { it.uid to (it.host ?: it.ip) }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // The whole search/filter panel is hidden by default (toggled by the 🔍 next to the tabs)
        // so the connection list gets the full screen height. Active filters still apply while
        // collapsed — the count line shows "· filtered" so it's never a silent surprise.
        if (searchOpen) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                label = { Text("Search apps, hosts, IPs, ports") },
                trailingIcon = {
                    if (query.isNotEmpty()) TextButton(onClick = { query = "" }) { Text("✕") }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ConnFilter.values().forEach { f ->
                    FilterChip(
                        selected = filter == f,
                        onClick = { filter = f; settings.setConnFilter(f.name) },
                        label = { Text(f.label) },
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ConnKind.values().forEach { k ->
                    FilterChip(
                        selected = kind == k,
                        onClick = { kind = k; settings.setConnKind(k.name) },
                        label = { Text(k.label) },
                    )
                }
            }
            // Bulk action on the filtered set — e.g. pick "Ads & trackers", then block them all.
            // Only offered while filtering, so it can never block the whole unfiltered list by accident.
            if (filtering && targets.isNotEmpty()) {
                TextButton(onClick = { confirmBlockAll = true }, modifier = Modifier.padding(top = 2.dp)) {
                    Text("Block all shown (${targets.size})", color = MaterialTheme.colorScheme.error)
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (filtering)
                    "showing $shown of ${events.size} · ${groups.size} app(s) · filtered"
                else "${events.size} connection(s) · ${groups.size} app(s)",
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.weight(1f).padding(vertical = 8.dp),
            )
            if (searchOpen) SortMenu(sort) { sort = it; settings.setConnSort(it.name) }
        }
        if (groups.isEmpty()) {
            Text(
                text = if (events.isEmpty()) "No connections captured yet."
                    else "No connections match your search/filter.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        LazyColumn(
            modifier = Modifier.fillMaxWidth().weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(groups, key = { it.first.uid }) { (app, visible) ->
                AppGroupRow(
                    app = app,
                    visible = visible,
                    annos = annos,
                    rules = rules,
                    repo = repo,
                    // While filtering, force every result open so matches are visible at a glance.
                    expanded = filtering || expanded[app.uid] == true,
                    expandToggleable = !filtering,
                    onToggle = { expanded[app.uid] = !(expanded[app.uid] ?: false) },
                    onChildClick = { ev -> hostDialog = HostTarget(app, ev) },
                )
            }
        }
    }

    hostDialog?.let { t -> HostDialog(t, repo) { hostDialog = null } }

    if (confirmBlockAll) {
        AlertDialog(
            onDismissRequest = { confirmBlockAll = false },
            title = { Text("Block all shown?") },
            text = {
                Text(
                    "Create deny rules for ${targets.size} destination(s) across ${groups.size} " +
                        "app(s). You can revert with Undo or restore them from Trash.",
                )
            },
            confirmButton = {
                TextButton(onClick = { repo.blockAllDest(targets); confirmBlockAll = false }) {
                    Text("Block all", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmBlockAll = false }) { Text("Cancel") } },
        )
    }
}

/** Substring match across the fields a user would search by. [q] is already lowercased. */
private fun matchesText(ev: ConnectionEvent, q: String): Boolean {
    if (q.isEmpty()) return true
    if (ev.host?.lowercase()?.contains(q) == true) return true
    if (ev.dstIp.lowercase().contains(q)) return true
    if (ev.appLabel?.lowercase()?.contains(q) == true) return true
    if (ev.packageName?.lowercase()?.contains(q) == true) return true
    if (ev.dstPort.toString().contains(q)) return true
    return ev.protocol.name.lowercase().contains(q)
}

private fun filterPass(anno: ConnAnno, filter: ConnFilter): Boolean = when (filter) {
    ConnFilter.All -> true
    // "effectively blocked" = a deny rule OR the ad-block backstop (rule verdict alone misses ads).
    ConnFilter.Allowed -> anno.verdict != Rule.ACTION_DENY && !anno.isAd
    ConnFilter.Blocked -> anno.verdict == Rule.ACTION_DENY || anno.isAd
    ConnFilter.Ads -> anno.isAd
}

private fun kindPass(ev: ConnectionEvent, kind: ConnKind): Boolean = when (kind) {
    ConnKind.Any -> true
    ConnKind.TCP -> ev.protocol == L4.TCP
    ConnKind.UDP -> ev.protocol == L4.UDP
    ConnKind.DNS -> ev.dstPort == 53
    ConnKind.HTTPS -> ev.dstPort == 443
    ConnKind.HTTP -> ev.dstPort == 80
}

/** Compact "Sort: <x> ▾" dropdown for the connection-group ordering. */
@Composable
private fun SortMenu(sort: ConnSort, onPick: (ConnSort) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }) { Text("Sort: ${sort.label} ▾") }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            ConnSort.values().forEach { s ->
                DropdownMenuItem(text = { Text(s.label) }, onClick = { onPick(s); open = false })
            }
        }
    }
}

@Composable
private fun AppGroupRow(
    app: AppInfo,
    visible: List<ConnectionEvent>,
    annos: Map<ConnectionEvent, ConnAnno>,
    rules: List<Rule>,
    repo: RuleRepository,
    expanded: Boolean,
    expandToggleable: Boolean,
    onToggle: () -> Unit,
    onChildClick: (ConnectionEvent) -> Unit,
) {
    // Whole-app verdict (app/global rules only — no host/ip/port/proto matcher).
    val appVerdict = repo.decideIn(rules, app.uid, app.packageName, 0, "", null, 0).action
    val blocked = app.events.count {
        val a = annos[it]
        a != null && (a.verdict == Rule.ACTION_DENY || a.isAd)
    }
    val status = appStatus(appVerdict, blocked, app.events.size)

    StatusCard(status.color()) {
        Row(
            modifier = Modifier.fillMaxWidth()
                .let { if (expandToggleable) it.clickable { onToggle() } else it }
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                if (expandToggleable) (if (expanded) "▾" else "▸") else "•",
                modifier = Modifier.padding(end = 10.dp),
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.label ?: "unknown",
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = "${app.events.size} destination(s)" +
                        if (blocked > 0) " · $blocked blocked" else "",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            StatusPill(status)
            Spacer(Modifier.width(8.dp))
            // Symmetric toggle: both directions write an explicit rule (visible in Rules),
            // so Connections and Rules always agree. Remove a rule via the Rules tab.
            TextButton(onClick = {
                repo.setAppRule(
                    app.uid, app.packageName, app.label,
                    if (appVerdict == Rule.ACTION_DENY) Rule.ACTION_ALLOW else Rule.ACTION_DENY,
                )
            }) {
                Text(if (appVerdict == Rule.ACTION_DENY) "Allow" else "Block")
            }
        }

        if (expanded) {
            visible.forEach { ev ->
                val anno = annos[ev] ?: ConnAnno(Rule.ACTION_ALLOW, false)
                ChildRow(ev, anno, onClick = { onChildClick(ev) })
            }
        }
    }
}

@Composable
private fun ChildRow(ev: ConnectionEvent, anno: ConnAnno, onClick: () -> Unit) {
    val palette = LocalStatusPalette.current
    // An ad-blocked flow is effectively blocked even when no user rule denies it — surface that
    // honestly instead of the rules-only "Allowed" the matcher would report.
    val (label, statusColor) = when {
        anno.verdict == Rule.ACTION_DENY -> FwStatus.Blocked.label to palette.blocked
        anno.isAd -> "Ad-blocked" to palette.blocked
        else -> FwStatus.Allowed.label to palette.allowed
    }
    Row(
        modifier = Modifier.fillMaxWidth().clickable { onClick() }
            .drawBehind { drawRect(color = statusColor, size = Size(3.dp.toPx(), size.height)) }
            .padding(start = 16.dp, end = 12.dp, top = 6.dp, bottom = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(ev.primary, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
            Text(
                text = "${ev.protocol} · IPv${ev.ipVersion} · ${ev.dstIp}:${ev.dstPort}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Pill(label, statusColor)
    }
}

@Composable
private fun HostDialog(t: HostTarget, repo: RuleRepository, onDismiss: () -> Unit) {
    val ev = t.ev
    val app = t.app
    val host = ev.host ?: ev.dstIp
    val appName = app.label ?: app.packageName ?: "this app"

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("$host in $appName") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                DialogAction("Allow $host") {
                    repo.setDestRule(app.uid, app.packageName, app.label, ev.host, ev.dstIp, Rule.ACTION_ALLOW)
                    onDismiss()
                }
                DialogAction("Block $host") {
                    repo.setDestRule(app.uid, app.packageName, app.label, ev.host, ev.dstIp, Rule.ACTION_DENY)
                    onDismiss()
                }
                DialogAction("Use app default") {
                    repo.setDestRule(app.uid, app.packageName, app.label, ev.host, ev.dstIp, null)
                    onDismiss()
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun DialogAction(label: String, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Text(label, modifier = Modifier.fillMaxWidth())
    }
}

// --- status: color-coded states used across the dashboard ---
// Colours come from the theme-aware LocalStatusPalette (Theme.kt) so they stay legible in
// both light and dark mode.

private enum class FwStatus(val label: String) {
    Allowed("Allowed"),
    Partial("Partially blocked"),
    Blocked("Blocked"),
}

@Composable
private fun FwStatus.color(): Color {
    val p = LocalStatusPalette.current
    return when (this) {
        FwStatus.Allowed -> p.allowed
        FwStatus.Partial -> p.partial
        FwStatus.Blocked -> p.blocked
    }
}

private fun verdictStatus(verdict: Int): FwStatus =
    if (verdict == Rule.ACTION_DENY) FwStatus.Blocked else FwStatus.Allowed

/** Whole-app status: blocked (all), allowed (none), or partial (some destinations differ). */
private fun appStatus(appVerdict: Int, blocked: Int, total: Int): FwStatus = when {
    appVerdict == Rule.ACTION_DENY && blocked >= total -> FwStatus.Blocked
    appVerdict == Rule.ACTION_DENY -> FwStatus.Partial      // app blocked, some hosts allowed
    blocked == 0 -> FwStatus.Allowed
    else -> FwStatus.Partial                                 // app allowed, some hosts blocked
}

/** Pill: colored dot + label on a tinted, bordered background. */
@Composable
private fun StatusPill(status: FwStatus) = Pill(status.label, status.color())

@Composable
private fun Pill(label: String, color: Color) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.12f))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(6.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = color,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

/** Card with a color-coded left accent bar + a left→transparent status tint (no all-sides halo). */
@Composable
private fun StatusCard(color: Color, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .background(
                Brush.horizontalGradient(
                    0f to color.copy(alpha = 0.22f),
                    0.55f to Color.Transparent,
                )
            )
            .drawBehind { drawRect(color = color, size = Size(4.dp.toPx(), size.height)) }
            .padding(start = 4.dp),
        content = content,
    )
}

// --- Rules tab ---

@Composable
private fun RulesTab(repo: RuleRepository) {
    val rules by repo.allRules.collectAsStateWithLifecycle(initialValue = emptyList<Rule>())
    var showSave by remember { mutableStateOf(false) }
    var showSnapshots by remember { mutableStateOf(false) }
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "${rules.size} rule(s)",
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { showSave = true }) { Text("Snapshot") }
            TextButton(onClick = { showSnapshots = true }) { Text("Restore") }
        }
        if (rules.isEmpty()) {
            Text(
                text = "No rules yet. Expand an app and block it, or block a host inside it.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        LazyColumn(
            modifier = Modifier.fillMaxWidth().weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(rules, key = { it.id }) { rule -> RuleRow(rule, repo) }
        }
    }

    if (showSave) SaveSnapshotDialog(repo) { showSave = false }
    if (showSnapshots) SnapshotsDialog(repo) { showSnapshots = false }
}

@Composable
private fun SaveSnapshotDialog(repo: RuleRepository, onDismiss: () -> Unit) {
    val default = remember { snapshotStamp(System.currentTimeMillis()) }
    var name by remember { mutableStateOf(default) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Save snapshot") },
        text = {
            Column {
                Text("Save the current rules as a restore point.")
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text("Name") },
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { repo.saveSnapshot(name.ifBlank { default }); onDismiss() }) {
                Text("Save")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SnapshotsDialog(repo: RuleRepository, onDismiss: () -> Unit) {
    val snaps by repo.snapshots.collectAsStateWithLifecycle(initialValue = emptyList<Snapshot>())
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Snapshots") },
        text = {
            if (snaps.isEmpty()) {
                Text("No snapshots yet. Tap Snapshot to save the current rules as a restore point.")
            } else {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    snaps.forEach { s ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(s.label, fontWeight = FontWeight.SemiBold)
                                Text(
                                    text = "${s.ruleCount} rule(s) · ${snapshotStamp(s.ts)}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            TextButton(onClick = { repo.restoreSnapshot(s); onDismiss() }) { Text("Restore") }
                            TextButton(onClick = { repo.deleteSnapshot(s) }) { Text("Delete") }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

@Composable
private fun RuleRow(rule: Rule, repo: RuleRepository) {
    val status = verdictStatus(rule.action)
    // A disabled rule isn't enforced — show it muted/grey so it doesn't read as active.
    val muted = MaterialTheme.colorScheme.outline
    val accent = if (rule.enabled) status.color() else muted
    StatusCard(accent) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = ruleSummary(rule),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = if (rule.enabled) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (rule.enabled) StatusPill(status) else Pill("Disabled", muted)
            }
            Switch(checked = rule.enabled, onCheckedChange = { repo.setEnabled(rule, it) })
            TextButton(onClick = { repo.delete(rule) }) { Text("Delete") }
        }
    }
}

// --- Trash tab ---

@Composable
private fun TrashTab(repo: RuleRepository) {
    val trashed by repo.trashedRules.collectAsStateWithLifecycle(initialValue = emptyList<Rule>())
    var confirmWipe by remember { mutableStateOf(false) }
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "${trashed.size} in Trash · auto-deleted after ${TrashPurgeWorker.RETENTION_DAYS} days",
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { confirmWipe = true }) {
                Text("Secure wipe", color = MaterialTheme.colorScheme.error)
            }
        }
        if (trashed.isEmpty()) {
            Text(
                text = "Trash is empty. Deleting a rule moves it here; restore it any time within " +
                    "${TrashPurgeWorker.RETENTION_DAYS} days.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        LazyColumn(
            modifier = Modifier.fillMaxWidth().weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(trashed, key = { it.id }) { rule -> TrashRow(rule, repo) }
        }
    }

    if (confirmWipe) {
        AlertDialog(
            onDismissRequest = { confirmWipe = false },
            title = { Text("Secure wipe") },
            text = {
                Text(
                    "Permanently delete all trashed rules, snapshots, and the undo history. " +
                        "This can't be undone or restored. Your active rules and connection " +
                        "history are not affected.",
                )
            },
            confirmButton = {
                TextButton(onClick = { repo.secureWipe(); confirmWipe = false }) {
                    Text("Wipe", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmWipe = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun TrashRow(rule: Rule, repo: RuleRepository) {
    val status = verdictStatus(rule.action)
    val dayMs = 24L * 60 * 60 * 1000
    val daysLeft = rule.deletedAt?.let {
        ((it + TrashPurgeWorker.RETENTION_MS - System.currentTimeMillis()) / dayMs).coerceAtLeast(0)
    } ?: 0
    StatusCard(status.color()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = ruleSummary(rule),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "in trash · ${daysLeft}d left",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            TextButton(onClick = { repo.restore(rule) }) { Text("Restore") }
            TextButton(onClick = { repo.deleteForever(rule) }) { Text("Delete") }
        }
    }
}

// --- helpers ---

/** Bridge persistent history rows to the view model the Connections UI already uses. */
private fun ConnLog.toEvent(): ConnectionEvent = ConnectionEvent(
    timeMs = ts,
    ipVersion = ipVersion,
    protocol = when (proto) { 6 -> L4.TCP; 17 -> L4.UDP; else -> L4.OTHER },
    srcIp = "",
    srcPort = -1,
    dstIp = dstIp,
    dstPort = dstPort,
    uid = appUid,
    appLabel = appLabel,
    packageName = packageName,
    host = dstHost,
)

private fun protoNum(p: L4): Int = when (p) {
    L4.TCP -> 6
    L4.UDP -> 17
    else -> 0
}

private fun snapshotStamp(ts: Long): String =
    java.text.SimpleDateFormat("MMM d, HH:mm", java.util.Locale.getDefault())
        .format(java.util.Date(ts))

private fun ruleSummary(rule: Rule): String {
    val who = rule.appLabel ?: rule.packageName ?: rule.appUid?.let { "uid $it" } ?: "any app"
    val what = rule.host ?: rule.ip ?: "any host"
    val port = rule.port?.let { ":$it" } ?: ""
    return "$who → $what$port"
}
