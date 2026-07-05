package network.aegis.mesh.ui.screen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import network.aegis.mesh.ui.Routes

data class Peer(
    val id: String,
    val displayName: String,
    val state: String,
    val rssi: Int,
    val transport: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PeerListScreen(nav: NavController) {
    // Placeholder peer list — in production, observe from MeshForegroundService
    var peers by remember { mutableStateOf(listOf<Peer>()) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Peers") },
                actions = {
                    IconButton(onClick = { nav.navigate(Routes.SCAN) }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Scan")
                    }
                    IconButton(onClick = { nav.navigate(Routes.CHANNEL_LIST) }) {
                        Icon(Icons.Default.List, contentDescription = "Channels")
                    }
                    IconButton(onClick = { nav.navigate(Routes.SETTINGS) }) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { nav.navigate(Routes.SCAN) },
                icon = { Icon(Icons.Default.Bluetooth) },
                text = { Text("Discover") },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (peers.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Default.BluetoothDisabled,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(16.dp))
                        Text("No peers discovered", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Tap Discover to scan for nearby devices",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                LazyColumn {
                    items(peers) { peer ->
                        PeerRow(peer) { nav.navigate(Routes.chat(peer.id)) }
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun PeerRow(peer: Peer, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            when (peer.transport) {
                "ble" -> Icons.Default.Bluetooth
                "lora" -> Icons.Default.Wifi
                else -> Icons.Default.DeviceUnknown
            },
            contentDescription = peer.transport,
            tint = if (peer.state == "online") MaterialTheme.colorScheme.secondary
                   else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(peer.displayName, style = MaterialTheme.typography.bodyLarge)
            Text(
                "${peer.id.take(16)}…",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(peer.state, style = MaterialTheme.typography.labelSmall)
            Text("${peer.rssi} dBm", style = MaterialTheme.typography.bodySmall)
        }
    }
}
