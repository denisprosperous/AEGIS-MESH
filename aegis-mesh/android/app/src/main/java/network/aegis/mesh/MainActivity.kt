package network.aegis.mesh

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import dagger.hilt.android.AndroidEntryPoint
import network.aegis.mesh.ui.theme.AegisMeshTheme
import network.aegis.mesh.ui.AegisNavGraph
import network.aegis.mesh.ui.Routes
import java.io.File

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Audit fix: FLAG_SECURE — block screenshots (SECURITY.md mandate)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        // Audit fix: request runtime permissions on first launch
        val perms = arrayOf(
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_ADVERTISE,
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.POST_NOTIFICATIONS,
        )
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {}
            .launch(perms)

        // Determine start destination: onboarding if no identity, else peer list
        val hasIdentity = File(filesDir, "identity.enc").exists()
        val startDest = if (hasIdentity) Routes.PEER_LIST else Routes.ONBOARDING

        setContent {
            AegisMeshTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    AegisNavGraph(startDestination = startDest)
                }
            }
        }

        // Auto-start mesh service if identity exists
        if (hasIdentity) {
            MeshForegroundService.start(this)
        }
    }
}
