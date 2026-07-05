package network.aegis.mesh.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun PeerListScreen() {
    var peers by remember { mutableStateOf(listOf<PeerStub>()) }
    Column(modifier = Modifier.fillMaxSize()) {
        Text("Discovered peers", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(8.dp))
        if (peers.isEmpty()) {
            Text("No peers yet. Start the mesh service.", style = MaterialTheme.typography.bodySmall)
        } else {
            LazyColumn {
                items(peers) { p -> PeerRow(p); HorizontalDivider() }
            }
        }
    }
}

@Composable
private fun PeerRow(p: PeerStub) {
    Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), Arrangement.SpaceBetween) {
        Column { Text(p.name); Text(p.id, style = MaterialTheme.typography.bodySmall) }
        Column(horizontalAlignment = Alignment.End) { Text(p.state); Text("${p.rssi} dBm") }
    }
}

private data class PeerStub(val id: String, val name: String, val state: String, val rssi: Int)
