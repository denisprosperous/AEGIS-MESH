package network.aegis.mesh.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Tactical dark palette — the only option (OPSEC: light theme visible at distance).
val AegisColors = darkColorScheme(
    primary = Color(0xFFD69E2E),         // amber
    onPrimary = Color.Black,
    primaryContainer = Color(0xFF4A3700),
    onPrimaryContainer = Color(0xFFFFE082),
    secondary = Color(0xFF4FD1C5),        // cyan accent
    onSecondary = Color.Black,
    tertiary = Color(0xFFE53E3E),         // red for emergency
    onTertiary = Color.White,
    background = Color(0xFF0A0E14),       // near-black
    onBackground = Color(0xFFE2E8F0),
    surface = Color(0xFF111827),
    onSurface = Color(0xFFE2E8F0),
    surfaceVariant = Color(0xFF1F2937),
    onSurfaceVariant = Color(0xFF9CA3AF),
    error = Color(0xFFE53E3E),
    onError = Color.White,
    outline = Color(0xFF374151),
)

@Composable
fun AegisMeshTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = AegisColors,
        typography = Typography(),
        content = content,
    )
}
