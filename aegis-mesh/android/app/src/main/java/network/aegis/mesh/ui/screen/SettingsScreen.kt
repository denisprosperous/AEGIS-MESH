package network.aegis.mesh.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import network.aegis.mesh.ffi.AegisFFI

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(nav: NavController) {
    var displayName by remember { mutableStateOf("") }
    var identityId by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf("") }
    var paranoidMode by remember { mutableStateOf(true) }
    var ephemeralMessages by remember { mutableStateOf(true) }
    var screenshotBlock by remember { mutableStateOf(true) }

    // Load identity
    LaunchedEffect(Unit) {
        try {
            val context = nav.context
            val blob = context.openFileInput("identity.enc").use { it.readBytes() }
            // In production, get passphrase from secure prompt or biometric
            // For now, placeholder
            displayName = AegisFFI.getDisplayName(blob, "placeholder")
            identityId = AegisFFI.getIdentityId(blob, "placeholder")
            fingerprint = AegisFFI.getFingerprint(blob, "placeholder")
        } catch (_: Exception) {}
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = { nav.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            // Identity section
            Text("Identity", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Name", style = MaterialTheme.typography.labelSmall)
                    Text(displayName, style = MaterialTheme.typography.bodyLarge)
                    Spacer(Modifier.height(8.dp))
                    Text("ID", style = MaterialTheme.typography.labelSmall)
                    Text(identityId, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Text("Fingerprint", style = MaterialTheme.typography.labelSmall)
                    Text(fingerprint, style = MaterialTheme.typography.bodySmall)
                }
            }

            Spacer(Modifier.height(24.dp))
            Text("Security", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            ListItem(
                headlineContent = { Text("Paranoid mode") },
                supportingContent = { Text("Ephemeral messages, no persistence, screenshot block") },
                trailingContent = { Switch(checked = paranoidMode, onCheckedChange = { paranoidMode = it }) },
            )
            ListItem(
                headlineContent = { Text("Ephemeral messages") },
                supportingContent = { Text("Messages disappear by default (24h)") },
                trailingContent = { Switch(checked = ephemeralMessages, onCheckedChange = { ephemeralMessages = it }) },
            )
            ListItem(
                headlineContent = { Text("Block screenshots") },
                supportingContent = { Text("FLAG_SECURE on all activities") },
                trailingContent = { Switch(checked = screenshotBlock, onCheckedChange = { screenshotBlock = it }) },
            )

            Spacer(Modifier.height(24.dp))
            Text("Emergency", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    AegisFFI.emergencyWipe()
                    // Delete identity file
                    nav.context.deleteFile("identity.enc")
                    nav.navigate("onboarding") { popUpTo(0) }
                },
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("EMERGENCY WIPE") }
        }
    }
}
