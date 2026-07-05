package network.aegis.mesh.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Audit fix: dark theme only (light theme was OPSEC leak).
private val DarkColors = darkColorScheme(
    primary = Color(0xFFD69E2E),
    onPrimary = Color.Black,
    secondary = Color(0xFF4FD1C5),
    onSecondary = Color.Black,
    background = Color(0xFF0A0E14),
    onBackground = Color(0xFFE2E8F0),
    surface = Color(0xFF111827),
    onSurface = Color(0xFFE2E8F0),
    error = Color(0xFFE53E3E),
)

@Composable
fun AegisMeshTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkColors, typography = Typography(), content = content)
}
