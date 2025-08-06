package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class DataProtectionManager(private val context: Context) {

    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences

    // Nombre de la clave maestra para HMAC
    private val hmacKeyAlias = "hmac_key"

    // Constantes para la derivación de claves
    private val KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256"
    private val KEY_DERIVATION_ITERATIONS = 10000
    private val KEY_DERIVATION_KEY_SIZE = 256

    private val MASTER_KEY_ROTATION_KEY = "last_master_key_rotation_timestamp"

    // Alias por defecto de MasterKey
    private val DEFAULT_MASTER_KEY_ALIAS = MasterKey.DEFAULT_MASTER_KEY_ALIAS

    fun initialize() {
        try {
            // Rotar la clave maestra si es necesario antes de usarla
            rotateMasterKeyIfNecessary()

            // Obtener la clave maestra (se creará si no existe)
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            // Crear SharedPreferences encriptado
            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            // SharedPreferences normal para logs
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)

            // Inicializar la clave HMAC
            generateOrGetHmacKey()

        } catch (e: Exception) {
            encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
        }
    }

    // --- Rotación automática de claves ---

    private fun rotateMasterKeyIfNecessary() {
        val prefs = context.getSharedPreferences("key_rotation_prefs", Context.MODE_PRIVATE)
        val lastRotationTimestamp = prefs.getLong(MASTER_KEY_ROTATION_KEY, 0L)
        val thirtyDaysInMillis = 30L * 24 * 60 * 60 * 1000

        if (System.currentTimeMillis() - lastRotationTimestamp > thirtyDaysInMillis) {
            logAccess("KEY_MANAGEMENT", "Iniciando rotación de clave maestra...")
            try {
                // El alias por defecto para MasterKey se puede obtener directamente.
                val masterKeyAlias = DEFAULT_MASTER_KEY_ALIAS

                // Eliminar la clave maestra del Android Keystore.
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                if (keyStore.containsAlias(masterKeyAlias)) {
                    keyStore.deleteEntry(masterKeyAlias)
                    logAccess("KEY_MANAGEMENT", "Clave maestra antigua eliminada con éxito.")
                } else {
                    logAccess("KEY_MANAGEMENT", "No se encontró la clave maestra antigua para eliminar.")
                }

                // Actualiza la fecha de la última rotación. La próxima vez que se
                // acceda a MasterKey.Builder().build(), se creará una nueva clave.
                prefs.edit().putLong(MASTER_KEY_ROTATION_KEY, System.currentTimeMillis()).apply()
                logAccess("KEY_MANAGEMENT", "Clave maestra rotada con éxito. Se creará una nueva al próximo uso.")

            } catch (e: Exception) {
                logAccess("KEY_MANAGEMENT", "Fallo al rotar la clave maestra: ${e.message}")
            }
        }
    }

    // --- Verificación de integridad con HMAC ---

    // Genera o recupera una clave HMAC desde Android Keystore
    private fun generateOrGetHmacKey(): SecretKeySpec {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        if (!keyStore.containsAlias(hmacKeyAlias)) {
            val keyGenerator = KeyGenerator.getInstance("HmacSHA256", "AndroidKeyStore")
            keyGenerator.init(256)
            keyGenerator.generateKey()
        }

        val secretKeyEntry = keyStore.getEntry(hmacKeyAlias, null) as KeyStore.SecretKeyEntry
        return SecretKeySpec(secretKeyEntry.secretKey.encoded, "HmacSHA256")
    }

    // Almacena datos encriptados junto con su HMAC para verificación
    fun storeSecureDataWithIntegrity(key: String, value: String) {
        val hmacKey = generateOrGetHmacKey()
        val hmac = generateHmac(value, hmacKey)

        // Almacena el valor encriptado y su HMAC en una sola cadena
        val combinedData = "$value::$hmac"
        encryptedPrefs.edit().putString(key, combinedData).apply()
        logAccess("DATA_STORAGE_HMAC", "Dato almacenado con integridad: $key")
    }

    // Recupera y verifica la integridad de los datos
    fun getSecureDataAndVerify(key: String): String? {
        val combinedData = encryptedPrefs.getString(key, null)
        if (combinedData == null) {
            logAccess("DATA_ACCESS_HMAC", "Intento de acceso a dato inexistente: $key")
            return null
        }

        // Separa el valor del HMAC
        val parts = combinedData.split("::")
        if (parts.size != 2) {
            logAccess("DATA_ACCESS_HMAC", "Fallo en la estructura de datos para $key. Devolviendo nulo.")
            return null
        }
        val value = parts[0]
        val storedHmac = parts[1]

        val hmacKey = generateOrGetHmacKey()
        val calculatedHmac = generateHmac(value, hmacKey)

        if (calculatedHmac == storedHmac) {
            logAccess("DATA_ACCESS_HMAC", "Dato accedido y verificado: $key")
            return value
        } else {
            logAccess("DATA_INTEGRITY_FAIL", "Fallo en la verificación de integridad para $key.")
            return null
        }
    }

    // Genera un HMAC para una cadena de datos
    private fun generateHmac(data: String, key: SecretKeySpec): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        val hmacBytes = mac.doFinal(data.toByteArray())
        return Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
    }

    // --- Implementación de key derivation con salt único ---

    // Genera un salt criptográfico aleatorio
    fun generateSalt(): ByteArray {
        val salt = ByteArray(16) // 128 bits
        val secureRandom = java.security.SecureRandom()
        secureRandom.nextBytes(salt)
        return salt
    }

    // Deriva una clave a partir de una contraseña y un salt
    fun deriveKeyFromPassword(password: String, salt: ByteArray): ByteArray {
        val pbeKeySpec = PBEKeySpec(password.toCharArray(), salt, KEY_DERIVATION_ITERATIONS, KEY_DERIVATION_KEY_SIZE)
        val secretKeyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM)
        return secretKeyFactory.generateSecret(pbeKeySpec).encoded
    }

    // --- Funciones originales ---

    fun storeSecureData(key: String, value: String) {
        // La implementación original ahora se reemplaza por la que usa HMAC
        storeSecureDataWithIntegrity(key, value)
    }

    fun getSecureData(key: String): String? {
        // La implementación original ahora usa la verificación de integridad
        return getSecureDataAndVerify(key)
    }

    fun logAccess(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - $category: $action"

        val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\n$logEntry"
        }

        accessLogPrefs.edit().putString("logs", newLogs).apply()

        val logLines = newLogs.split("\n")
        if (logLines.size > 100) {
            val trimmedLogs = logLines.takeLast(100).joinToString("\n")
            accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
        }
    }

    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("logs", "") ?: ""
        return if (logsString.isEmpty()) {
            emptyList()
        } else {
            logsString.split("\n").reversed()
        }
    }

    fun clearAllData() {
        encryptedPrefs.edit().clear().apply()
        accessLogPrefs.edit().clear().apply()
        logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }

    fun getDataProtectionInfo(): Map<String, String> {
        return mapOf(
            "Encriptación" to "AES-256-GCM",
            "Almacenamiento" to "Local encriptado",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Estado de seguridad" to "Activo"
        )
    }

    fun anonymizeData(data: String): String {
        return data.replace(Regex("[0-9]"), "*")
            .replace(Regex("[A-Za-z]{3,}"), "***")
    }
}