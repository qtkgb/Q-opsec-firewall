package com.qopsec.firewall.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qopsec.firewall.data.AppDatabase
import com.qopsec.firewall.data.AppUsage
import com.qopsec.firewall.data.UsageBucket
import com.qopsec.firewall.vpn.TrafficSampler
import kotlinx.coroutines.launch
import java.util.Calendar
import java.util.Locale

// Series colors, CVD-validated against both the dark and light surfaces (dataviz check).
// Distinct from the reserved status colors (green/amber/red = allow/partial/block).
private val WifiColor = Color(0xFF4F8CFF)
private val MobileColor = Color(0xFFD9548A)

private enum class Period(val label: String) { HOURLY("Hourly"), DAILY("Daily"), WEEKLY("Weekly"), MONTHLY("Monthly") }

private enum class AppSort(val label: String) { HIGHEST("Highest"), LOWEST("Lowest"), ALPHA("A–Z") }

/** One app's aggregated usage over the visible range. */
private data class AppRow(val label: String, val rx: Long, val tx: Long) {
    val total get() = rx + tx
}

/** One chart bar: an aggregated time bucket. */
private data class Bar(
    val axisLabel: String,     // short x-axis label ("14:00", "12", "Jul")
    val detailLabel: String,   // full label for the tap-to-inspect line
    val wifiRx: Long, val wifiTx: Long, val mobileRx: Long, val mobileTx: Long,
) {
    val wifi get() = wifiRx + wifiTx
    val mobile get() = mobileRx + mobileTx
    val total get() = wifi + mobile
}

/**
 * Stats tab — how much traffic ran through the firewall, WiFi vs mobile, as a stacked
 * bar chart over the selected period. Data accumulates only while the tunnel is up.
 */
@Composable
fun StatsTab() {
    val context = LocalContext.current
    val dao = remember { AppDatabase.get(context).usageDao() }
    val scope = rememberCoroutineScope()
    var period by remember { mutableStateOf(Period.DAILY) }
    var confirmClear by remember { mutableStateOf(false) }
    var appSort by remember { mutableStateOf(AppSort.HIGHEST) }

    val since = remember(period) { rangeStart(period) }
    val rows by remember(period) { dao.since(since) }.collectAsStateWithLifecycle(initialValue = emptyList())
    val appUsage by remember(period) { dao.appsSince(since) }.collectAsStateWithLifecycle(initialValue = emptyList())
    val bars = remember(rows, period) { aggregate(rows, period) }
    val appRows = remember(appUsage, appSort) { aggregateApps(appUsage, appSort) }
    val hasData = bars.any { it.total > 0 }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Period.entries.forEach { p ->
                FilterChip(selected = period == p, onClick = { period = p }, label = { Text(p.label) })
            }
        }

        Text(
            "Traffic through the firewall — measured while it runs",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 8.dp),
        )

        if (!hasData) {
            Box(modifier = Modifier.fillMaxWidth().height(240.dp), contentAlignment = Alignment.Center) {
                Text(
                    "No traffic measured yet.\nStats accumulate while the firewall is running.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            UsageChart(bars = bars, modifier = Modifier.fillMaxWidth().height(240.dp).padding(top = 10.dp))
        }

        // Legend (2 series ⇒ always shown); text wears text tokens, dots carry the identity.
        Row(
            modifier = Modifier.padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            LegendDot(WifiColor, "WiFi")
            LegendDot(MobileColor, "Mobile")
        }

        val wifiRx = bars.sumOf { it.wifiRx }
        val wifiTx = bars.sumOf { it.wifiTx }
        val mobRx = bars.sumOf { it.mobileRx }
        val mobTx = bars.sumOf { it.mobileTx }
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TotalCard("WiFi", wifiRx, wifiTx, Modifier.weight(1f))
            TotalCard("Mobile", mobRx, mobTx, Modifier.weight(1f))
            TotalCard("Total", wifiRx + mobRx, wifiTx + mobTx, Modifier.weight(1f))
        }

        // Per-app breakdown for the same range: which apps move the data — and whether a
        // Block visibly shrinks an app's appetite (the ads-are-eating-my-data check).
        if (appRows.isNotEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Per app (${appRows.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                AppSort.entries.forEach { s ->
                    FilterChip(
                        selected = appSort == s,
                        onClick = { appSort = s },
                        label = { Text(s.label, style = MaterialTheme.typography.labelMedium) },
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
            }
            val maxTotal = appRows.maxOf { it.total }.coerceAtLeast(1)
            appRows.forEach { app ->
                Column(modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            app.label,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                        )
                        Text(fmtBytes(app.total), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        // Magnitude bar: single hue (accent), length ∝ share of the biggest app.
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .height(6.dp)
                                .clip(RoundedCornerShape(3.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant),
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth(fraction = (app.total.toFloat() / maxTotal).coerceIn(0.01f, 1f))
                                    .height(6.dp)
                                    .clip(RoundedCornerShape(3.dp))
                                    .background(WifiColor),
                            )
                        }
                        Text(
                            "↓ ${fmtBytes(app.rx)} · ↑ ${fmtBytes(app.tx)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(start = 10.dp),
                        )
                    }
                }
            }
        }

        OutlinedButton(
            onClick = { confirmClear = true },
            modifier = Modifier.padding(top = 16.dp, bottom = 12.dp),
        ) {
            Text("Clear all stats", color = LocalStatusPalette.current.blocked)
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear all stats?") },
            text = { Text("Deletes all recorded traffic statistics. This can't be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmClear = false
                    scope.launch {
                        dao.clearAll()
                        dao.clearAllApps()
                    }
                }) { Text("Clear", color = LocalStatusPalette.current.blocked) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun LegendDot(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(modifier = Modifier.size(10.dp).clip(CircleShape).background(color))
        Text(label, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun TotalCard(title: String, rx: Long, tx: Long, modifier: Modifier = Modifier) {
    Card(modifier = modifier, shape = RoundedCornerShape(12.dp)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(title, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(fmtBytes(rx + tx), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "↓ ${fmtBytes(rx)} · ↑ ${fmtBytes(tx)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Stacked bar chart (WiFi bottom / Mobile top), tap a bar to inspect its values. */
@Composable
private fun UsageChart(bars: List<Bar>, modifier: Modifier = Modifier) {
    var selected by remember(bars) { mutableStateOf(-1) }
    val gridColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.18f)
    val labelColor = MaterialTheme.colorScheme.onSurfaceVariant
    val density = LocalDensity.current
    val labelPx = with(density) { 10.sp.toPx() }
    val gapPx = with(density) { 2.dp.toPx() }
    val cornerPx = with(density) { 4.dp.toPx() }

    Column(modifier = modifier) {
        // Tap-to-inspect detail line (kept above the plot so it never covers a bar).
        val detail = bars.getOrNull(selected)
        Text(
            text = detail?.let {
                "${it.detailLabel} — WiFi ${fmtBytes(it.wifi)} · Mobile ${fmtBytes(it.mobile)}"
            } ?: "Tap a bar for details",
            style = MaterialTheme.typography.bodySmall,
            color = if (detail != null) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(top = 6.dp)
                .pointerInput(bars) {
                    detectTapGestures { pos ->
                        val n = bars.size
                        if (n > 0) {
                            val slot = size.width.toFloat() / n
                            val idx = (pos.x / slot).toInt().coerceIn(0, n - 1)
                            selected = if (selected == idx) -1 else idx
                        }
                    }
                },
        ) {
            val n = bars.size
            if (n == 0) return@Canvas
            val max = bars.maxOf { it.total }.coerceAtLeast(1)
            val axisH = labelPx * 1.6f
            val plotH = size.height - axisH
            val slot = size.width / n
            val barW = (slot * 0.72f).coerceAtMost(with(density) { 34.dp.toPx() })

            val paint = android.graphics.Paint().apply {
                color = android.graphics.Color.argb(
                    (labelColor.alpha * 255).toInt(),
                    (labelColor.red * 255).toInt(), (labelColor.green * 255).toInt(), (labelColor.blue * 255).toInt(),
                )
                textSize = labelPx
                isAntiAlias = true
            }

            // Recessive grid: half + full of the y-max, labels in muted ink.
            for (frac in listOf(0.5f, 1f)) {
                val y = plotH * (1f - frac)
                drawLine(gridColor, Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
                drawContext.canvas.nativeCanvas.drawText(
                    fmtBytes((max * frac).toLong()), 2f, y - 4f, paint,
                )
            }
            drawLine(gridColor, Offset(0f, plotH), Offset(size.width, plotH), strokeWidth = 1.5f)

            val labelEvery = when {
                n <= 12 -> 2
                n <= 24 -> 4
                else -> 5
            }
            bars.forEachIndexed { i, b ->
                val x = slot * i + (slot - barW) / 2f
                val dim = selected >= 0 && selected != i
                val alpha = if (dim) 0.45f else 1f
                val hWifi = plotH * b.wifi / max
                val hMob = plotH * b.mobile / max
                // WiFi sits on the baseline; Mobile stacks above with a 2dp surface gap.
                if (b.wifi > 0) {
                    val top = plotH - hWifi
                    if (b.mobile > 0) {
                        drawRect(WifiColor.copy(alpha = alpha), Offset(x, top), Size(barW, hWifi))
                    } else {
                        drawRoundedTop(x, top, barW, hWifi, cornerPx, WifiColor.copy(alpha = alpha))
                    }
                }
                if (b.mobile > 0) {
                    val gap = if (b.wifi > 0) gapPx else 0f
                    val top = plotH - hWifi - gap - hMob
                    drawRoundedTop(x, top, barW, hMob, cornerPx, MobileColor.copy(alpha = alpha))
                }
                if (i % labelEvery == 0) {
                    drawContext.canvas.nativeCanvas.drawText(
                        b.axisLabel, x, size.height - labelPx * 0.3f, paint,
                    )
                }
            }
        }
    }
}

/** Rect with only its top corners rounded (the data-end of the topmost stack segment). */
private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawRoundedTop(
    x: Float, top: Float, w: Float, h: Float, corner: Float, color: Color,
) {
    if (h <= 0f) return
    val r = corner.coerceAtMost(h)
    val path = Path().apply {
        addRoundRect(
            RoundRect(
                rect = Rect(Offset(x, top), Size(w, h)),
                topLeft = CornerRadius(r), topRight = CornerRadius(r),
                bottomLeft = CornerRadius.Zero, bottomRight = CornerRadius.Zero,
            ),
        )
    }
    drawPath(path, color)
}

// --- bucketing ---

private fun rangeStart(p: Period): Long = boundaries(p).first()

/** Ascending bucket start-times for the period (the last one is the current bucket). */
private fun boundaries(p: Period): List<Long> {
    val cal = Calendar.getInstance()
    cal.firstDayOfWeek = Calendar.MONDAY
    cal.set(Calendar.MINUTE, 0); cal.set(Calendar.SECOND, 0); cal.set(Calendar.MILLISECOND, 0)
    return when (p) {
        Period.HOURLY -> {
            val h = cal.timeInMillis
            (23 downTo 0).map { h - it * TrafficSampler.HOUR_MS }
        }
        Period.DAILY -> {
            cal.set(Calendar.HOUR_OF_DAY, 0)
            (29 downTo 0).map { d ->
                (cal.clone() as Calendar).apply { add(Calendar.DAY_OF_YEAR, -d) }.timeInMillis
            }
        }
        Period.WEEKLY -> {
            cal.set(Calendar.HOUR_OF_DAY, 0)
            cal.set(Calendar.DAY_OF_WEEK, Calendar.MONDAY)
            (11 downTo 0).map { w ->
                (cal.clone() as Calendar).apply { add(Calendar.WEEK_OF_YEAR, -w) }.timeInMillis
            }
        }
        Period.MONTHLY -> {
            cal.set(Calendar.HOUR_OF_DAY, 0)
            cal.set(Calendar.DAY_OF_MONTH, 1)
            (11 downTo 0).map { m ->
                (cal.clone() as Calendar).apply { add(Calendar.MONTH, -m) }.timeInMillis
            }
        }
    }
}

private fun aggregate(rows: List<UsageBucket>, p: Period): List<Bar> {
    val starts = boundaries(p)
    val wifiRx = LongArray(starts.size); val wifiTx = LongArray(starts.size)
    val mobRx = LongArray(starts.size); val mobTx = LongArray(starts.size)
    var i = 0
    for (row in rows) {   // rows and starts are both ascending — single pass
        while (i + 1 < starts.size && row.hourStart >= starts[i + 1]) i++
        if (row.hourStart < starts[i]) continue
        wifiRx[i] += row.wifiRx; wifiTx[i] += row.wifiTx
        mobRx[i] += row.mobileRx; mobTx[i] += row.mobileTx
    }
    val cal = Calendar.getInstance()
    return starts.mapIndexed { idx, start ->
        cal.timeInMillis = start
        val (axis, detail) = when (p) {
            Period.HOURLY -> {
                val h = cal.get(Calendar.HOUR_OF_DAY)
                String.format(Locale.US, "%02d", h) to String.format(Locale.US, "%02d:00–%02d:59", h, h)
            }
            Period.DAILY -> {
                val d = cal.get(Calendar.DAY_OF_MONTH)
                "$d" to String.format(
                    Locale.US, "%d %s", d,
                    cal.getDisplayName(Calendar.MONTH, Calendar.SHORT, Locale.getDefault()),
                )
            }
            Period.WEEKLY -> {
                val label = String.format(
                    Locale.US, "%d.%02d", cal.get(Calendar.DAY_OF_MONTH), cal.get(Calendar.MONTH) + 1,
                )
                label to "Week of $label"
            }
            Period.MONTHLY -> {
                val m = cal.getDisplayName(Calendar.MONTH, Calendar.SHORT, Locale.getDefault()) ?: ""
                m to "$m ${cal.get(Calendar.YEAR)}"
            }
        }
        Bar(axis, detail, wifiRx[idx], wifiTx[idx], mobRx[idx], mobTx[idx])
    }
}

/** Sum per-app hourly rows over the visible range and order per the selected sort. */
private fun aggregateApps(rows: List<AppUsage>, sort: AppSort): List<AppRow> {
    val byApp = HashMap<String, AppRow>()
    for (r in rows) {
        val prev = byApp[r.appKey]
        byApp[r.appKey] = AppRow(
            label = r.label,
            rx = (prev?.rx ?: 0) + r.rx,
            tx = (prev?.tx ?: 0) + r.tx,
        )
    }
    val list = byApp.values.filter { it.total > 0 }
    return when (sort) {
        AppSort.HIGHEST -> list.sortedByDescending { it.total }
        AppSort.LOWEST -> list.sortedBy { it.total }
        AppSort.ALPHA -> list.sortedBy { it.label.lowercase() }
    }
}

private fun fmtBytes(b: Long): String = when {
    b >= 1L shl 30 -> String.format(Locale.US, "%.2f GB", b / 1073741824.0)
    b >= 1L shl 20 -> String.format(Locale.US, "%.1f MB", b / 1048576.0)
    b >= 1L shl 10 -> String.format(Locale.US, "%.1f KB", b / 1024.0)
    else -> "$b B"
}
