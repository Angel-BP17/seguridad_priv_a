# Evaluación Técnica: Análisis y Mejora de Seguridad en Aplicación Android

## Introducción
Esta evaluación técnica se basa en una aplicación Android que implementa un sistema de demostración de permisos y protección de datos. La aplicación utiliza tecnologías modernas como Kotlin, Android Security Crypto, SQLCipher y patrones de arquitectura MVVM.

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)
Analiza el archivo `DataProtectionManager.kt` y responde:
- ¿Qué método de encriptación se utiliza para proteger datos sensibles?
    Se utiliza EncryptedSharedPreferences con los siguientes esquemas de cifrado:
      - MasterKey.KeyScheme.AES256_GCM,
      - EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      - EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
- Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging
    1. El archivo guarda los accesos en SharedPreferences sin ningún tipo de encriptación:
       accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
       Esto permite a cualquier app con root o privilegios leer los logs de acceso, lo que podría exponer patrones de uso o nombres de claves.
    2. El método logAccess guarda el nombre de la clave accedida:
       logAccess("DATA_ACCESS", "Dato accedido: $key")
       Si key contiene información sensible (como "password", "token", etc.), se estaría exponiendo indirectamente esa sensibilidad.
- ¿Qué sucede si falla la inicialización del sistema de encriptación?
  Si ocurre una excepción durante la creación del MasterKey o de las EncryptedSharedPreferences, se captura mediante try-catch, y el sistema recupera utilizando SharedPreferences sin encriptación (secure_prefs_fallback).
### 1.2 Permisos y Manifiesto (2 puntos)
Examina `AndroidManifest.xml` y `MainActivity.kt`:
- Lista todos los permisos peligrosos declarados en el manifiesto
  Los siguientes permisos son considerados peligrosos según la documentación oficial de Android (requieren consentimiento explícito del usuario en tiempo de ejecución):
  	android.permission.CAMERA
  	android.permission.READ_EXTERNAL_STORAGE (obsoleto en versiones recientes, reemplazado por otros como READ_MEDIA_IMAGES)
  	android.permission.READ_MEDIA_IMAGES (peligroso a partir de Android 13)
  	android.permission.RECORD_AUDIO
  	android.permission.READ_CONTACTS
  	android.permission.CALL_PHONE
  	android.permission.SEND_SMS
  	android.permission.ACCESS_COARSE_LOCATION
- ¿Qué patrón se utiliza para solicitar permisos en runtime?
  Patrón usado: ActivityResultContracts.RequestPermission
- Identifica qué configuración de seguridad previene backups automáticos
  <application
  android:allowBackup="false"
  ...
  />
  La línea android:allowBackup="false" en el AndroidManifest.xml desactiva las copias de seguridad automáticas del sistema Android (como las que realiza Google Drive o adb backup).
### 1.3 Gestión de Archivos (3 puntos)
Revisa `CameraActivity.kt` y `file_paths.xml`:
- ¿Cómo se implementa la compartición segura de archivos de imágenes?
  1. Creación del archivo en almacenamiento externo privado
     private fun createImageFile(): File {
     val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
     .format(Date())
     val storageDir = File(getExternalFilesDir(null), "Pictures")
     if (!storageDir.exists()) storageDir.mkdirs()
     return File(storageDir, "JPEG_${timeStamp}_.jpg")
     }
  2. Obtención del URI seguro con FileProvider
     val photoFile = createImageFile()
     currentPhotoUri = FileProvider.getUriForFile(
     this,
     "com.example.seguridad_priv_a.fileprovider",
     photoFile
     )
  3. Lanzar la cámara pasando ese URI
     takePictureLauncher.launch(currentPhotoUri)
  4. Definición de rutas permitidas en file_paths.xml
    <?xml version="1.0" encoding="utf-8"?>
    <paths xmlns:android="http://schemas.android.com/apk/res/android">
        <external-files-path name="my_images" path="Pictures" />
        <external-files-path name="my_audio"  path="Audio"    />
    </paths>
  - ¿Qué autoridad se utiliza para el FileProvider?
    En el AndroidManifest.xml aparece registrado así:
      <provider
        android:name="androidx.core.content.FileProvider"
        android:authorities="com.example.seguridad_priv_a.fileprovider"
        android:exported="false"
        android:grantUriPermissions="true">
        <meta-data
          android:name="android.support.FILE_PROVIDER_PATHS"
          android:resource="@xml/file_paths" />
      </provider>
    Por lo tanto, la authority es:
      com.example.seguridad_priv_a.fileprovider
- Explica por qué no se debe usar `file://` URIs directamente
  1. Seguridad y permisos
     - Un URI file:// expone la ruta absoluta en el sistema de archivos, lo que puede filtrar información de la estructura interna de la app.
     - No permite gestionar permisos de lectura/escritura de forma granular al pasar el URI en un Intent.
  2. Compatibilidad (“StrictMode”)
     - Desde Android 7.0 (API 24), el sistema lanza una excepción FileUriExposedException si intentas compartir un URI file:// con otro proceso.
  3. Control de acceso temporal
     - Con un content:// vía FileProvider, puedes usar los flags Intent.FLAG_GRANT_READ_URI_PERMISSION y/o FLAG_GRANT_WRITE_URI_PERMISSION para otorgar acceso solo durante la vida del Intent, sin exponer el archivo globalmente.
  Por estas razones, siempre se recomienda envolver los archivos en un FileProvider y compartir content:// URIs en lugar de file://.
## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)
Modifica `DataProtectionManager.kt` para implementar:
- Rotación automática de claves maestras cada 30 días
- Verificación de integridad de datos encriptados usando HMAC
- Implementación de key derivation con salt único por usuario

```kotlin
// Ejemplo de estructura esperada
fun rotateEncryptionKey(): Boolean {
    // Tu implementación aquí
}

fun verifyDataIntegrity(key: String): Boolean {
    // Tu implementación aquí
}
```

### 2.2 Sistema de Auditoría Avanzado (3 puntos)
Crea una nueva clase `SecurityAuditManager` que:
- Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)
- Implemente rate limiting para operaciones sensibles
- Genere alertas cuando se detecten patrones anómalos
- Exporte logs en formato JSON firmado digitalmente

### 2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en `DataProtectionActivity.kt`:
- Integra BiometricPrompt API para proteger el acceso a logs
- Implementa fallback a PIN/Pattern si biometría no está disponible
- Añade timeout de sesión tras inactividad de 5 minutos

## Parte 3: Arquitectura de Seguridad Avanzada (15-20 puntos)

### 3.1 Implementación de Zero-Trust Architecture (3 puntos)
Diseña e implementa un sistema que:
- Valide cada operación sensible independientemente
- Implemente principio de menor privilegio por contexto
- Mantenga sesiones de seguridad con tokens temporales
- Incluya attestation de integridad de la aplicación

### 3.2 Protección Contra Ingeniería Inversa (3 puntos)
Implementa medidas anti-tampering:
- Detección de debugging activo y emuladores
- Obfuscación de strings sensibles y constantes criptográficas
- Verificación de firma digital de la aplicación en runtime
- Implementación de certificate pinning para comunicaciones futuras

### 3.3 Framework de Anonimización Avanzado (2 puntos)
Mejora el método `anonymizeData()` actual implementando:
- Algoritmos de k-anonimity y l-diversity
- Differential privacy para datos numéricos
- Técnicas de data masking específicas por tipo de dato
- Sistema de políticas de retención configurables

```kotlin
class AdvancedAnonymizer {
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData>
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any
}
```

### 3.4 Análisis Forense y Compliance (2 puntos)
Desarrolla un sistema de análisis forense que:
- Mantenga chain of custody para evidencias digitales
- Implemente logs tamper-evident usando blockchain local
- Genere reportes de compliance GDPR/CCPA automáticos
- Incluya herramientas de investigación de incidentes

## Criterios de Evaluación

### Puntuación Base (0-7 puntos):
- Correcta identificación de vulnerabilidades y patrones de seguridad
- Comprensión de conceptos básicos de Android Security
- Documentación clara de hallazgos

### Puntuación Intermedia (8-14 puntos):
- Implementación funcional de mejoras de seguridad
- Código limpio siguiendo principios SOLID
- Manejo adecuado de excepciones y edge cases
- Pruebas unitarias para componentes críticos

### Puntuación Avanzada (15-20 puntos):
- Arquitectura robusta y escalable
- Implementación de patrones de seguridad industry-standard
- Consideración de amenazas emergentes y mitigaciones
- Documentación técnica completa con diagramas de arquitectura
- Análisis de rendimiento y optimización de operaciones criptográficas

## Entregables Requeridos

1. **Código fuente** de todas las implementaciones solicitadas
2. **Informe técnico** detallando vulnerabilidades encontradas y soluciones aplicadas
3. **Diagramas de arquitectura** para componentes de seguridad nuevos
4. **Suite de pruebas** automatizadas para validar medidas de seguridad
5. **Manual de deployment** con consideraciones de seguridad para producción

## Tiempo Estimado
- Parte 1: 2-3 horas
- Parte 2: 4-6 horas  
- Parte 3: 8-12 horas

## Recursos Permitidos
- Documentación oficial de Android
- OWASP Mobile Security Guidelines
- Libraries de seguridad open source
- Stack Overflow y comunidades técnicas

---

**Nota**: Esta evaluación requiere conocimientos sólidos en seguridad móvil, criptografía aplicada y arquitecturas Android modernas. Se valorará especialmente la capacidad de aplicar principios de security-by-design y el pensamiento crítico en la identificación de vectores de ataque.