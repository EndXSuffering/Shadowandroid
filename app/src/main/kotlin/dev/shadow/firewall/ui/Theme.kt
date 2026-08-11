package dev.shadow.firewall.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val LightColors = lightColorScheme(
    primary = Color(0xFF1F6FEB),
    secondary = Color(0xFF3D7A5A),
    error = Color(0xFFB3261E),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF7FB0FF),
    secondary = Color(0xFF87D6AC),
    error = Color(0xFFF2B8B5),
)

/** Colours used for verdicts, kept in one place so the list and detail views agree. */
object VerdictColors {
    val blocked: Color @Composable get() = MaterialTheme.colorScheme.error
    val allowed: Color @Composable get() = MaterialTheme.colorScheme.secondary
}

@Composable
fun ShadowFirewallTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colors = when {
        // Material You where the platform offers it, our own palette otherwise.
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        darkTheme -> DarkColors
        else -> LightColors
    }
    MaterialTheme(colorScheme = colors, content = content)
}
