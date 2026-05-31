# SignerXadesBesEc

Firma de comprobantes electrónicos XML para **SRI Ecuador** usando certificados PKCS#12 (`.p12` / `.pfx`), generando firmas **XAdES-BES enveloped** en .NET 10 con APIs nativas.

---

## Compatibilidad con certificados

El código es **agnóstico a la entidad emisora** del certificado. Cualquier `.p12` válido funciona en el proceso de firma — la validación de la CA la realiza el SRI en su servidor cuando recibe el comprobante.

**Único requisito técnico del código:** el certificado debe usar **RSA** (el SRI solo acepta RSA-SHA256; ECDSA y DSA no están soportados por la Ficha Técnica v2.32). El código lo detecta y devuelve error descriptivo si el certificado no es RSA.

Entidades certificadoras autorizadas por el SRI (2025):
- Banco Central del Ecuador — https://www.eci.bce.ec
- Security Data — https://www.securitydata.net.ec
- ANFAC — https://firmaselectronicas.ec
- Consejo de la Judicatura — https://www.icert.fje.gob.ec
- UANATACA Ecuador — https://store.uanataca.ec
- ARGOSDATA — https://www.argosdata.com.ec
- Eclipsoft — https://firmas.eclipsoft.com
- Lazzate / Enext — https://enext.ec
- Firma Segura EC — https://firmaseguraec.com

Todos emiten archivos `.p12` RSA estándar — cualquiera de ellos funciona igual en este código.

---

## Requisitos

- .NET 10 SDK — https://dotnet.microsoft.com/download/dotnet/10.0
- Certificado digital ecuatoriano RSA en formato PKCS#12 (`.p12` / `.pfx`)
- Visual Studio 2022 17.12+ o VS Code con extensión C#

---

## Compilar y ejecutar

```powershell
# Restaurar dependencias
dotnet restore

# Compilar
dotnet build

# Ejecutar (modo interactivo)
dotnet run

# Ejecutar con argumentos
dotnet run -- <cert.p12> <password> [input.xml] [output.xml]

# Ejemplo
dotnet run -- mi_cert.p12 MiPassword entrada.xml salida_firmada.xml

# Publicar autónomo (incluye runtime .NET)
dotnet publish -c Release -r win-x64 --self-contained
```

Salida de compilación limpia esperada:
```
Build succeeded in 4s    (0 errors, 0 warnings)
```

---

## Uso en código

### Para SRI Ecuador (recomendado)

```csharp
var certBytes = File.ReadAllBytes("certificado.p12");
var signer = new SignDocumentSriEcuador();
string? xmlFirmado = null;

bool ok = signer.Sign(
    xmlUnsigned: File.ReadAllText("factura.xml"),
    password: "mi_password",
    certificate: certBytes,
    claveAcceso: "0412202501099999999900110010010000000011234567819", // 49 dígitos
    xmlSigned: ref xmlFirmado
);

if (ok && xmlFirmado != null)
    File.WriteAllText("factura_firmada.xml", xmlFirmado);
```

### Genérico XAdES-BES (no específico SRI)

```csharp
var signer = new SignDocument();
string? xmlFirmado = null;
signer.Sign(xmlUnsigned, password, certBytes, ref xmlFirmado);
```

### Integración como API (ASP.NET)

```csharp
[HttpPost("api/firma/xades")]
public IActionResult Firmar([FromBody] FirmarRequest req)
{
    var certBytes = Convert.FromBase64String(req.CertificadoBase64);
    var signer = new SignDocumentSriEcuador();
    string? xmlFirmado = null;

    if (!signer.Sign(req.Xml, req.Password, certBytes, req.ClaveAcceso, ref xmlFirmado))
        return StatusCode(500, "Error firmando");

    return Ok(new { xmlFirmado });
}
```

---

## Clases

| Clase | Propósito |
|-------|-----------|
| `SignDocumentSriEcuador` | Firma XAdES-BES conforme a Ficha Técnica SRI v2.32 — **usar esta para SRI** |
| `SignDocument` | Firma XAdES-BES genérica estándar ETSI (no específica SRI) |
| `SignedXmlWithIdResolution` | Subclase interna que resuelve `id="comprobante"` (lowercase) en .NET |

---

## Conformidad SRI (Ficha Técnica v2.32)

| Requisito SRI | Estado |
|---|---|
| XAdES-BES ETSI TS 101 903 v1.3.2 | ✅ |
| Algoritmo RSA-SHA256 | ✅ |
| Digest SHA-256 | ✅ |
| Canonicalización C14N explícita | ✅ |
| Transformadas enveloped + C14N en referencia al contenido | ✅ |
| IDs basados en clave de acceso (no GUIDs) | ✅ |
| Referencia a SignedProperties antes que referencia al contenido | ✅ |
| KeyInfo con X509Certificate + RSAKeyValue | ✅ |
| SigningTime zona horaria Ecuador (UTC-5, `-05:00`) | ✅ |
| SignedDataObjectProperties con DataObjectFormat | ✅ |
| Firma como último elemento del XML | ✅ |
| Elemento raíz con `id="comprobante"` | ✅ |
| Validación: cert RSA obligatorio | ✅ |
| Validación: clave de acceso 49 dígitos | ✅ |
| Validación: cert no expirado (verificar antes de firmar) | ✅ (Program.cs) |

---

## Clave de acceso (49 dígitos)

```
Formato: DDMMAAAATCRRRRRRRRRRRRRRAAEEESSSSSSSSSCCCCCCCCV
         │       ││ │           ││ ││ │        │       │
         │       ││ │           ││ ││ │        │       └─ Dígito verificador (módulo 11)
         │       ││ │           ││ ││ │        └───────── Código numérico (8 dígitos)
         │       ││ │           ││ ││ └────────────────── Secuencial (9 dígitos)
         │       ││ │           ││ │└──────────────────── Punto de emisión (3 dígitos)
         │       ││ │           ││ └───────────────────── Establecimiento (3 dígitos)
         │       ││ │           │└─────────────────────── Ambiente: 1=pruebas, 2=producción
         │       ││ │           └──────────────────────── RUC (13 dígitos)
         │       ││ └──────────────────────────────────── Tipo comprobante (01=Factura, etc.)
         │       │└─────────────────────────────────────── Tipo emisión (1=Normal)
         └───────┘──────────────────────────────────────── Fecha emisión (DDMMAAAA)
```

El dígito verificador usa módulo 11 con pesos 2..7 (ciclando), de derecha a izquierda.

---

## Estructura XML resultante

```xml
<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.1.0">
    <!-- ... datos del comprobante ... -->

    <!-- Firma — SIEMPRE último elemento -->
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#"
                  Id="Signature{claveAcceso}">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <!-- 1. Referencia a SignedProperties (primero) -->
            <ds:Reference Id="SignedPropertiesID{claveAcceso}"
                          Type="http://uri.etsi.org/01903#SignedProperties"
                          URI="#Signature{claveAcceso}-SignedProperties{claveAcceso}">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>...</ds:DigestValue>
            </ds:Reference>
            <!-- 2. Referencia al contenido (segundo) -->
            <ds:Reference Id="Reference-ID-{claveAcceso}" URI="#comprobante">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>...</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue Id="SignatureValue{claveAcceso}">...</ds:SignatureValue>
        <ds:KeyInfo Id="Certificate{claveAcceso}">
            <ds:X509Data><ds:X509Certificate>...</ds:X509Certificate></ds:X509Data>
            <ds:KeyValue><ds:RSAKeyValue><ds:Modulus>...</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>
        </ds:KeyInfo>
        <ds:Object Id="Signature{claveAcceso}-Object{claveAcceso}">
            <etsi:QualifyingProperties Target="#Signature{claveAcceso}">
                <etsi:SignedProperties Id="Signature{claveAcceso}-SignedProperties{claveAcceso}">
                    <etsi:SignedSignatureProperties>
                        <etsi:SigningTime>2025-12-04T10:30:00-05:00</etsi:SigningTime>
                        <etsi:SigningCertificate>...</etsi:SigningCertificate>
                    </etsi:SignedSignatureProperties>
                    <etsi:SignedDataObjectProperties>
                        <etsi:DataObjectFormat ObjectReference="#Reference-ID-{claveAcceso}">
                            <etsi:Description>contenido comprobante</etsi:Description>
                            <etsi:MimeType>text/xml</etsi:MimeType>
                        </etsi:DataObjectFormat>
                    </etsi:SignedDataObjectProperties>
                </etsi:SignedProperties>
            </etsi:QualifyingProperties>
        </ds:Object>
    </ds:Signature>
</factura>
```

---

## Ambientes SRI

| Ambiente | URL Recepción |
|----------|---------------|
| Pruebas (certificación) | `https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline` |
| Producción | `https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline` |

El XML firmado se envía como Base64 al método `validarComprobante` del WSDL del SRI.

---

## Errores comunes

| Error | Causa | Solución |
|-------|-------|----------|
| `El certificado no usa RSA` | Certificado ECDSA o DSA | Obtener certificado RSA de CA autorizada |
| `Certificate is expired` | Certificado vencido | Renovar `.p12` con la CA |
| `La clave de acceso debe tener 49 dígitos` | Clave incorrecta | Verificar cálculo de clave y dígito verificador |
| `Failed to load certificate` | Password incorrecta o archivo corrupto | Verificar credenciales o reemitir |
| Firma rechazada por SRI | CA no autorizada | Usar certificado de entidad en la lista SRI |
| Firma rechazada por SRI | Ambiente incorrecto (1 vs 2) | Verificar campo `<ambiente>` en el XML |

---

## Seguridad

- No almacenar el password en texto plano — usar `ProtectedData` (DPAPI) o variables de entorno
- Permisos NTFS mínimos al archivo `.p12`
- Validar tamaño y bien formado del XML de entrada antes de firmar
- Registrar thumbprint y serial del certificado en cada operación de firma
- Alertar cuando el certificado tenga menos de 30 días para vencer

---

## Dependencias

| Paquete | Versión | Uso |
|---------|---------|-----|
| `System.Security.Cryptography.Xml` | 10.0.6 | Motor XML-DSig / XAdES |
| `System.Security.Cryptography.Pkcs` | 10.0.6 | Carga de certificados PKCS#12 |

---

## Mejoras futuras

- Soporte XAdES-T (timestamp de autoridad TSA)
- Generación automática de clave de acceso con módulo 11
- Cliente SOAP integrado para envío al SRI
- Generación de RIDE (PDF)
- Validación offline contra XSD del SRI
- Soporte ECDSA si el SRI lo habilita en futuras versiones

---

## Referencias

- [Ficha Técnica SRI v2.32](https://www.sri.gob.ec/facturacion-electronica) — especificación oficial
- [ETSI TS 101 903](https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/) — estándar XAdES
- [System.Security.Cryptography.Xml](https://docs.microsoft.com/dotnet/api/system.security.cryptography.xml) — docs .NET

---

## Licencia

MIT — ver archivo `LICENSE`.
