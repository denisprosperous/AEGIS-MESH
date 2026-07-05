package network.aegis.mesh.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController

/**
 * BLE scan screen — shows scanning progress + discovered devices.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(nav: NavController) {
    var scanning by remember { mutableStateOf(true) }
    var devices by remember { mutableStateOf(listOf<String>()) }

    LaunchedEffect(Unit) {
        // TODO: start BLE scan via MeshForegroundService
        // For now, simulate
        kotlinx.coroutines.delay(5000)
        scanning = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scanning") },
                navigationIcon = {
                    TextButton(onClick = { nav.popBackStack() }) { Text("Cancel") }
                },
            )
        },
    ) { padding ->
        Box(
            Modifier.fillMaxSize().padding(padding),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (scanning) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text("Scanning for BLE devices…")
                } else {
                    Text("Scan complete. ${devices.size} devices found.")
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { nav.popBackStack() }) { Text("Done") }
                }
            }
        }
    }
}
