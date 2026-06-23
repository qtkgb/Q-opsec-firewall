package com.qopsec.firewall.ui

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.qopsec.firewall.data.ThemeMode

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4F8CFF),
    secondary = Color(0xFF6EE7B7),
    background = Color(0xFF0F1117),
    surface = Color(0xFF171A23),
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF2563EB),
    secondary = Color(0xFF059669),
    background = Color(0xFFF7F8FA),
    surface = Color(0xFFFFFFFF),
)

/** Status colors tuned per theme so they stay legible (amber is unreadable on white at full sat). */
data class StatusPalette(val allowed: Color, val partial: Color, val blocked: Color)

private val DarkStatus = StatusPalette(Color(0xFF22C55E), Color(0xFFF59E0B), Color(0xFFEF4444))
private val LightStatus = StatusPalette(Color(0xFF15803D), Color(0xFFB45309), Color(0xFFDC2626))

val LocalStatusPalette = staticCompositionLocalOf { DarkStatus }

@Composable
fun FirewallTheme(themeMode: ThemeMode = ThemeMode.SYSTEM, content: @Composable () -> Unit) {
    val dark = when (themeMode) {
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }

    // Status-bar icon contrast must follow the theme (dark icons on a light bar).
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !dark
        }
    }

    CompositionLocalProvider(LocalStatusPalette provides if (dark) DarkStatus else LightStatus) {
        MaterialTheme(colorScheme = if (dark) DarkColors else LightColors, content = content)
    }
}
