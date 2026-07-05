package network.aegis.mesh.ui.screen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import network.aegis.mesh.ui.Routes

data class Channel(
    val id: String,
    val name: String,
    val memberCount: Int,
    val lastMessage: String?,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelListScreen(nav: NavController) {
    var channels by remember { mutableStateOf(listOf<Channel>()) }
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Channels") },
                navigationIcon = {
                    IconButton(onClick = { nav.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showCreate = true }) {
                Icon(Icons.Default.Add, contentDescription = "Create channel")
            }
        },
    ) { padding ->
        if (channels.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("No channels. Tap + to create one.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(Modifier.padding(padding)) {
                items(channels) { ch ->
                    Row(
                        Modifier.fillMaxWidth().clickable { nav.navigate(Routes.channelChat(ch.id)) }
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Default.People, contentDescription = null)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("# ${ch.name}", style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "${ch.memberCount} members",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }

    if (showCreate) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showCreate = false },
            title = { Text("New Channel") },
            text = {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Channel name") },
                    singleLine = true,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    if (name.isNotBlank()) {
                        // TODO: create channel via Rust core
                        channels = channels + Channel(
                            id = System.currentTimeMillis().toString(),
                            name = name,
                            memberCount = 1,
                            lastMessage = null,
                        )
                    }
                    showCreate = false
                }) { Text("Create") }
            },
            dismissButton = { TextButton(onClick = { showCreate = false }) { Text("Cancel") } },
        )
    }
}

private val Icons.Default.People get() = androidx.compose.material.icons.Icons.Filled.Group

@Composable
fun ChannelChatScreen(nav: NavController, channelId: String) {
    // Reuse ChatScreen with channel context
    ChatScreen(nav, peerId = "#$channelId")
}
