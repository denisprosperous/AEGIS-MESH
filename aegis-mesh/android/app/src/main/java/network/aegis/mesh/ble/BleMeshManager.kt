package network.aegis.mesh.ble

import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresPermission
import network.aegis.mesh.ffi.AegisFFI
import java.util.*

/**
 * BLE manager — handles scan, advertise, GATT connection.
 * Bridges bytes to/from the Rust core via AegisFFI.
 */
class BleMeshManager(private val context: Context) {

    companion object {
        // Audit fix: real 128-bit UUID (was "aegis-mesh-ble-v1")
        val SERVICE_UUID: UUID = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e")
        val CHAR_INCOMING_UUID: UUID = UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
        val CHAR_OUTGOING_UUID: UUID = UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? get() = bluetoothManager.adapter
    private var gatt: BluetoothGatt? = null

    @RequiresPermission(allOf = [android.Manifest.permission.BLUETOOTH_SCAN, android.Manifest.permission.BLUETOOTH_CONNECT])
    fun startScan(callback: ScanCallback) {
        val scanner = bluetoothManager.adapter?.bluetoothLeScanner ?: return
        val filter = ScanFilter.Builder()
            .setServiceUuid(ScanResultUuid(SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        scanner.startScan(listOf(filter), settings, callback)
    }

    @RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)
    fun stopScan(callback: ScanCallback) {
        bluetoothManager.adapter?.bluetoothLeScanner?.stopScan(callback)
    }

    @RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)
    fun connect(device: BluetoothDevice) {
        gatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    @RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)
    fun disconnect() {
        gatt?.disconnect()
        gatt?.close()
        gatt = null
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                gatt.discoverServices()
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val service = gatt.getService(SERVICE_UUID) ?: return
            val char = service.getCharacteristic(CHAR_OUTGOING_UUID) ?: return
            gatt.setCharacteristicNotification(char, true)
            val cccd = char.getDescriptor(CCCD_UUID)
            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            gatt.writeDescriptor(cccd)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            // Audit fix: inject received bytes into Rust core
            AegisFFI.injectBleBytes(value)
        }
    }

    /** Drain outgoing envelopes from Rust and send via GATT writes. */
    @RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)
    fun flushOutgoing() {
        val gatt = this.gatt ?: return
        val service = gatt.getService(SERVICE_UUID) ?: return
        val char = service.getCharacteristic(CHAR_INCOMING_UUID) ?: return
        // Note: drainOutgoingBle would be called here if exposed via FFI
        // For now, placeholder
    }
}

// Helper for ScanFilter UUID
private fun ScanResultUuid(uuid: UUID) = android.os.ParcelUuid(uuid)
