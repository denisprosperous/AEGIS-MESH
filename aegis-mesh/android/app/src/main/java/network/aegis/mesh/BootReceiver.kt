package network.aegis.mesh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Audit fix: auto-start mesh after device reboot (was missing). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            MeshForegroundService.start(context)
        }
    }
}
