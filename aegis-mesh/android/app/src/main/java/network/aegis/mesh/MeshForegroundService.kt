package network.aegis.mesh

import android.app.*
import android.content.*
import android.os.*
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

class MeshForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "aegis_mesh_service"
        const val NOTIFICATION_ID = 1
        fun start(context: Context) {
            val intent = Intent(context, MeshForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                context.startForegroundService(intent)
            else context.startService(intent)
        }
        fun stop(context: Context) {
            context.stopService(Intent(context, MeshForegroundService::class.java))
        }
    }

    private lateinit var wakeLock: PowerManager.WakeLock

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        // Audit fix: acquire wakelock (was missing — BLE scans paused when screen off).
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "aegis:mesh")
        wakeLock.acquire(12 * 60 * 60 * 1000L) // 12 hours
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AEGIS-MESH")
            .setContentText("Mesh running")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            // Audit fix: content intent (was missing — notification was dead-end).
            .setContentIntent(PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE,
            ))
            .build()
        // Audit fix: correct startForeground for Android 14 (was deprecated 2-arg overload).
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID, notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
        return START_STICKY
    }

    // Audit fix: onDestroy (was missing — leaked resources on stop).
    override fun onDestroy() {
        if (this::wakeLock.isInitialized && wakeLock.isHeld) wakeLock.release()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "AEGIS-MESH", NotificationManager.IMPORTANCE_LOW)
            channel.description = "Keeps the mesh running in the background"
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
}
