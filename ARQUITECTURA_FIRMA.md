# Arquitectura de Firma de Comprobantes Electrónicos (.p12) - .NET Framework 4.8.1

Este documento describe la arquitectura implementada para la firma de comprobantes electrónicos usando certificados **PKCS#12 (.p12 / .pfx)** bajo **.NET Framework 4.8.1**, así como alternativas de integración (CLI, API, Servicio Windows) y buenas prácticas para despliegue en producción.

---
## 1. Objetivo
Firmar un XML (ej. comprobante electrónico con nodo raíz `comprobante`) aplicando una firma **XAdES-BES enveloped** utilizando un certificado digital con clave privada contenido en un archivo PKCS#12.

---
## 2. Componentes Principales

| Componente | Rol | Notas |
|------------|-----|-------|
| `Program` | Punto de entrada (console app). | Permite ejecución interactiva o por argumentos. |
| `SignDocument` | Lógica de firma XAdES-BES. | Usa librerías Java portadas (espacio de nombres `es.mityc.*`). |
| `PassStoreKS` | Soporte para acceso a KeyStore. | Maneja password del PKCS#12. |
| Librerías `es.mityc.*` | Motor XAdES. | Requiere interoperabilidad Java/.NET (ej: IKVM). |

---
## 3. Flujo de Firma (Resumen)
1. Leer parámetros: XML a firmar, certificado (.p12) y contraseña.
2. Cargar KeyStore PKCS#12 → obtener certificado X509 + clave privada.
3. Construir DOM del XML (`org.w3c.dom.Document`).
4. Configurar `DataToSign`: formato XAdES_BES, esquema 1.3.2, modo enveloped.
5. Agregar objeto a firmar (nodo `comprobante`).
6. Ejecutar `FirmaXML.signFile(...)`.
7. Serializar XML firmado y devolverlo.

---
## 4. Validaciones Implementadas
- Verificación de expiración del certificado antes de intentar firmar.
- Manejo de errores controlado (mensajes en consola).
- Verifica existencia de archivo antes de cargarlo.

---
## 5. Modos de Integración
### 5.1. Ejecución por Consola (Actual)
```
SignerXadesBesEc.exe <ruta-cert.p12> <password> [xml-entrada] [xml-salida]
```
Si faltan parámetros, entra en modo interactivo.

### 5.2. Exposición como API (ASP.NET Web API)
Escenario: Un sistema externo envía XML y obtiene el XML firmado.

Ejemplo (controlador simplificado):
```csharp
[HttpPost]
[Route("api/firma/xades")] 
public IHttpActionResult Firmar(FirmarRequest req)
{
    // Validaciones básicas
    if (string.IsNullOrWhiteSpace(req.Xml) || string.IsNullOrWhiteSpace(req.Password))
        return BadRequest("Datos incompletos");

    // Opción A: Certificado en Base64
    var certBytes = Convert.FromBase64String(req.CertificadoBase64);

    var signer = new SignDocument();
    string xmlFirmado = null;
    if (!signer.Sign(req.Xml, req.Password, certBytes, ref xmlFirmado))
        return InternalServerError(new Exception("Error firmando"));

    return Ok(new { xmlFirmado });
}
public class FirmarRequest { public string Xml { get; set; } public string CertificadoBase64 { get; set; } public string Password { get; set; } }
```
Consideraciones:
- Limitar tamaño de XML (DoS prevention).
- Registrar auditoría (quién firma, cuándo).
- Evitar exponer stacktrace a clientes.

### 5.3. Servicio Windows (Procesamiento en Lote)
Escenario: Directorio de entrada (drop folder) o cola de mensajes.

Pseudocódigo del ciclo:
```csharp
protected override void OnStart(string[] args)
{
    _timer = new System.Timers.Timer(5000);
    _timer.Elapsed += (s, e) => ProcesarPendientes();
    _timer.Start();
}

private void ProcesarPendientes()
{
    foreach (var file in Directory.GetFiles(_inputDir, "*.xml"))
    {
        try
        {
            var xml = File.ReadAllText(file);
            var certBytes = CargarCertificado(); // Desde archivo seguro / DPAPI / Windows Cert Store
            string firmado = null;
            if (new SignDocument().Sign(xml, _password, certBytes, ref firmado))
            {
                File.WriteAllText(Path.Combine(_outDir, Path.GetFileName(file)), firmado);
                MoverAProcesados(file);
            }
            else
            {
                MoverAErrores(file);
            }
        }
        catch (Exception ex)
        {
            LogError(ex);
        }
    }
}
```
Recomendado:
- Usar `EventLog` + logs estructurados.
- Supervisión con servicios tipo Windows Task Scheduler + HealthCheck.

### 5.4. Certificado en Memoria / Bytes
Opciones de provisión de certificado:
- Archivo físico `.p12` en disco protegido (ACL restringida). 
- Valor Base64 proveniente de: base de datos, Azure Key Vault, HashiCorp Vault.
- Cargado una vez y cacheado en un singleton seguro (sin exponer password).

---
## 6. Estrategias para Pasar Parámetros
| Escenario | Certificado | Password | XML | Output |
|-----------|-------------|----------|-----|--------|
| CLI | Ruta archivo | Argumento / prompt | Ruta / STDIN / prompt | Archivo o STDOUT |
| API | Base64 en body | Campo JSON (encriptar en tránsito) | Body JSON | JSON (Base64 o texto) |
| Servicio Windows | Archivo seguro / Vault | Config segura (DPAPI / Encriptado) | Archivo en carpeta / cola | Archivo en carpeta salida |

---
## 7. Seguridad
1. No almacenar la contraseña en texto plano (usar DPAPI, ProtectedData, o secret manager).
2. Controlar permisos NTFS del archivo .p12 (solo cuenta de servicio).
3. Limpiar buffers sensibles (en escenarios críticos considerar `Array.Clear`).
4. Evitar escribir XML firmado en carpetas compartidas sin cifrado si contiene datos sensibles.
5. Registrar huella (thumbprint) y serie del certificado para trazabilidad.
6. Validar que el XML de entrada no contenga ataques XXE (usar fábricas de parser seguros). Actualmente `DocumentBuilderFactory` debe configurarse adicionalmente para endurecerse.

Configuraciones adicionales sugeridas (endurecimiento parser):
```csharp
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
(Agregar según compatibilidad con las librerías usadas.)

---
## 8. Despliegue a Producción
### 8.1. Console / Batch
- Empaquetar binarios + dependencias.
- Configurar script de ejecución (.bat / PowerShell) con variables.

### 8.2. API
- Hospedar en IIS (AppPool aislado, .NET v4.0 CLR).
- Activar logging (ETW / Serilog / ELK / AppInsights - si se migra a Core en futuro).
- Configurar límites de request (`maxRequestLength`).

### 8.3. Servicio Windows
- Instalar con `sc create` o `InstallUtil.exe`.
- Ejecutar bajo cuenta de servicio con mínimos privilegios.
- Monitorear con: SCOM, Zabbix, Prometheus exporter (custom), etc.

### 8.4. Versionado / CI
- Usar tagging (ej: `v1.0.0`).
- Pipeline: build → pruebas unitarias (si se añaden) → firma de ensamblado (opcional) → despliegue.

### 8.5. Observabilidad
- Logs estructurados (JSON) para correlación.
- Identificadores de transacción por cada firma.
- Métricas: tiempo medio de firma, cantidad de errores, expiración próxima de certificados.

---
## 9. Errores Comunes y Solución
| Problema | Causa Probable | Solución |
|----------|----------------|----------|
| "Certificate is expired" | Certificado vencido | Renovar y distribuir nuevo .p12 |
| Null en `xmlSigned` | Nodo `comprobante` no existe | Validar estructura antes de firmar |
| "Failed to load certificate" | Password incorrecta / archivo corrupto | Verificar credenciales / reemitir |
| Excepción de parser | XML mal formado | Validar XML antes de enviar |
| Rendimiento bajo | Firma en serie alta concurrencia | Pool de procesos / servicio escalado |

---
## 10. Futuras Mejores
- Migración a .NET 8 (cuando se reemplacen dependencias Java o se use una lib nativa XAdES).
- Añadir soporte de políticas (XAdES-EPES) si normativa lo requiere.
- Cache del KeyStore para reducir overhead de carga repetida.
- Validación de cadena de confianza (OCSP / CRL) previa a firmar.

---
## 11. Ejemplo Rápido (CLI)
```
SignerXadesBesEc.exe certs\\miCert.p12 MiPassword entrada.xml salida_firmada.xml
```
Sin XML de entrada (usa XML mínimo):
```
SignerXadesBesEc.exe certs\\miCert.p12 MiPassword
```

---
## 12. Ejemplo de Uso con Certificado Base64 (API Interna)
```csharp
var request = new HttpRequestMessage(HttpMethod.Post, "https://host/api/firma/xades");
request.Content = new StringContent(JsonConvert.SerializeObject(new {
    Xml = File.ReadAllText("entrada.xml"),
    CertificadoBase64 = Convert.ToBase64String(File.ReadAllBytes("certs/miCert.p12")),
    Password = "MiPasswordSegura"
}), Encoding.UTF8, "application/json");
```

---
## 13. Notas Finales
- Esta solución está diseñada específicamente para **.NET Framework 4.8.1**.
- Si se requiere contenedorización, podría hacerse con Windows Containers (no Linux) dado el runtime.
- Revisar licencias de las librerías `es.mityc` antes de entornos comerciales.

---
## 14. Glosario
| Término | Descripción |
|---------|-------------|
| XAdES-BES | Perfil básico de firma electrónica XML avanzado. |
| Enveloped | Tipo de firma donde `<Signature>` se inserta dentro del XML original. |
| PKCS#12 | Formato que empaqueta certificado + clave privada. |
| Thumbprint | Hash identificador del certificado (huella). |

---