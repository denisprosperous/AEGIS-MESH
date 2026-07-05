package network.aegis.mesh.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import network.aegis.mesh.ui.Routes
import network.aegis.mesh.ffi.AegisFFI
import network.aegis.mesh.MeshForegroundService
import android.widget.Toast
import androidx.compose.ui.platform.LocalContext

/**
 * Onboarding screen — first-run identity creation.
 * Generates a BIP39 mnemonic + Ed25519 keypair, encrypts with passphrase.
 */
@Composable
fun OnboardingScreen(nav: NavController) {
    val context = LocalContext.current
    var displayName by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var passphraseConfirm by remember { mutableStateOf("") }
    var showMnemonic by remember { mutableStateOf(false) }
    var mnemonic by remember { mutableStateOf("") }
    var identityId by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("AEGIS-MESH", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Censorship-resistant communication",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(32.dp))

        if (!showMnemonic) {
            // Identity creation form
            OutlinedTextField(
                value = displayName,
                onValueChange = { displayName = it },
                label = { Text("Display name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase (min 8 chars)") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = passphraseConfirm,
                onValueChange = { passphraseConfirm = it },
                label = { Text("Confirm passphrase") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
            }
            Button(
                onClick = {
                    error = null
                    if (displayName.isBlank()) { error = "Enter a display name"; return@Button }
                    if (passphrase.length < 8) { error = "Passphrase must be at least 8 characters"; return@Button }
                    if (passphrase != passphraseConfirm) { error = "Passphrases don't match"; return@Button }
                    loading = true
                    try {
                        // Save blob to internal storage
                        val blob = AegisFFI.generateIdentity(displayName, passphrase)
                        context.openFileOutput("identity.enc", android.content.Context.MODE_PRIVATE).use {
                            it.write(blob)
                        }
                        identityId = AegisFFI.getIdentityId(blob, passphrase)
                        fingerprint = AegisFFI.getFingerprint(blob, passphrase)
                        // Mnemonic would be revealed separately — for onboarding we show a placeholder
                        mnemonic = "Run `aegis identity reveal` to view your mnemonic"
                        showMnemonic = true
                        // Start the mesh service
                        MeshForegroundService.start(context)
                    } catch (e: Exception) {
                        error = "Failed: ${e.message}"
                    }
                    loading = false
                },
                enabled = !loading,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (loading) "Generating..." else "Create Identity") }
        } else {
            // Show identity details + mnemonic warning
            Text("Identity Created", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(16.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("ID", style = MaterialTheme.typography.labelSmall)
                    Text(identityId, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Text("Fingerprint", style = MaterialTheme.typography.labelSmall)
                    Text(fingerprint, style = MaterialTheme.typography.bodySmall)
                }
            }
            Spacer(Modifier.height(16.dp))
            Text(
                "Save your mnemonic offline. It is the ONLY way to recover your identity.",
                color = MaterialTheme.colorScheme.tertiary,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { nav.navigate(Routes.PEER_LIST) { popUpTo(Routes.ONBOARDING) { inclusive = true } } },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Continue to Mesh") }
        }
    }
}
