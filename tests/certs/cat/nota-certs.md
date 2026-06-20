

---

## 📁 Estructura completa

```
certs/
├── ca/                          # Autoridad de Certificación (CA) raíz
├── server/                      # Certificado del servidor (Envoy / PEP)
├── clients/                     # Certificados de clientes (usuarios/roles)
│   ├── soc_admin
│   ├── operatore_ancona
│   ├── capitano_claudia
│   └── intruso
├── devices/                     # Certificados de dispositivos (identidad de equipo)
│   ├── D-001
│   ├── D-002
│   └── D-SOC
└── mongodb/                     # Certificados para la base de datos MongoDB
```

---

## 🔐 Explicación detallada de cada subdirectorio

### 1. `ca/` – Autoridad de Certificación Raíz

| Fichero   | Descripción |
|-----------|-------------|
| `ca.crt`  | Certificado autofirmado de la CA raíz. Es la **raíz de confianza** del sistema. Todos los demás certificados (servidores, clientes, dispositivos) son firmados por esta CA. |
| `ca.key`  | **Clave privada** de la CA. Extremadamente sensible; debe protegerse (rotada, almacenada de forma segura). |

**Función en ZTA**:  
La CA raíz emite y valida todas las identidades digitales del ecosistema. Ningún componente (Envoy, MongoDB, cliente) confía en nadie que no tenga un certificado firmado por esta CA.

---

### 2. `server/` – Certificado del Servidor (Envoy / PEP)

| Fichero      | Descripción |
|--------------|-------------|
| `server.crt` | Certificado del servidor (Envoy Proxy / PEP). Contiene la identidad del servidor y su clave pública. |
| `server.key` | **Clave privada** del servidor. Solo el PEP conoce esta clave. |
| `ca.crt`     | Copia del CA raíz para que el servidor pueda validar clientes (cadena de confianza). |

**Función en ZTA**:  
Este certificado se usa en el lado del **Policy Enforcement Point (PEP)** – Envoy. Cuando un cliente se conecta a Envoy (puerto 8443), Envoy presenta este certificado para ser autenticado por el cliente. A su vez, Envoy usa el `ca.crt` para verificar la identidad del cliente (**mTLS bidireccional**).

---

### 3. `clients/` – Certificados de Clientes (Usuarios/Roles)

Cada cliente tiene una carpeta con su nombre de rol:

| Carpeta               | Identidad / Rol                  | Red        |
|-----------------------|----------------------------------|------------|
| `soc_admin`           | `ruolo_gestione_flotta` (Fleet Manager) | corporate_net |
| `operatore_ancona`    | `ruolo_banchina` (Dock Operator) | vpn_net    |
| `capitano_claudia`    | `ruolo_equipaggio` (Crew)        | satellite_net |
| `intruso`             | `ruolo_non_autorizzato` (Intruder) | public_net |

**Archivos comunes en cada carpeta**:

| Fichero       | Descripción |
|---------------|-------------|
| `client.crt`  | Certificado del cliente, firmado por la CA raíz. Identifica al usuario/rol. |
| `client.key`  | **Clave privada** del cliente. El cliente debe mantenerla segura. |
| `ca.crt`      | Copia del CA raíz para que el cliente pueda verificar al servidor (Envoy). |

**Función en ZTA**:  
Cada cliente presenta su certificado (`client.crt`) al conectar a Envoy. Envoy verifica que el certificado esté firmado por la CA raíz y extrae el **Common Name (CN)** u otros atributos (ej. `OU=ruolo_gestione_flotta`) para pasarlos a OPA (PDP) como parte de la decisión de autorización. Esto implementa el principio **"Never Trust, Always Verify"**: incluso si el cliente está en una red corporativa, debe demostrar quién es mediante su certificado.

---

### 4. `devices/` – Certificados de Dispositivos (Identidad de Equipo)

| Carpeta | Descripción |
|---------|-------------|
| `D-001` | Dispositivo 1 (ej. terminal de muelle) |
| `D-002` | Dispositivo 2 (ej. sensor IoT) |
| `D-SOC` | Dispositivo del SOC (Security Operations Center) |

Cada carpeta contiene un `ca.crt` (copia de la CA raíz). En un despliegue completo, también contendrían `device.crt` y `device.key` con la identidad del dispositivo.

**Función en ZTA**:  
Los dispositivos (no solo usuarios) tienen identidades digitales propias. Esto permite aplicar políticas basadas en **atributos del dispositivo** (ABAC), como "solo dispositivos aprobados pueden acceder a datos de la flota". Es parte del **Device Trust** del modelo Zero Trust.

---

### 5. `mongodb/` – Certificados para MongoDB

| Fichero         | Descripción |
|-----------------|-------------|
| `ca.crt`        | CA raíz para validar conexiones entrantes a MongoDB. |
| `mongodb.crt`   | Certificado del servidor MongoDB. |
| `mongodb.key`   | **Clave privada** de MongoDB. |
| `mongodb.pem`   | Combinación de `mongodb.crt` + `mongodb.key` en un solo archivo (formato PEM). MongoDB lo usa para habilitar TLS. |

**Función en ZTA**:  
La base de datos **db_primary** (MongoDB) se comunica exclusivamente con la capa API (`api_backend`) mediante TLS mutuo. El archivo `mongodb.pem` se monta en el contenedor de MongoDB para que el servidor se autentique ante los clientes (API). Además, puede exigir que los clientes (API) presenten un certificado firmado por la CA, reforzando el aislamiento.

---

## 🔑 Flujo completo de mTLS (basado en estos certificados)

1. **Cliente** (ej. `soc_admin`) → inicia conexión a **Envoy** (PEP) en puerto 8443.
2. Envoy presenta su `server.crt`. El cliente lo verifica usando su copia de `ca.crt`.
3. Cliente presenta su `client.crt`. Envoy lo verifica usando su copia de `ca.crt`.
4. **Ambas partes quedan autenticadas mutuamente**.
5. Envoy extrae el CN (identidad) del cliente y lo envía a **OPA** (PDP) para la decisión de política (allow/deny).
6. Si es permitido, Envoy reenvía la petición a `api_backend` (también con mTLS opcional).
7. API se conecta a MongoDB usando `mongodb.pem` para autenticación TLS.

---

## ⚠️ Consideraciones de seguridad

- **`.gitignore`**: Todos los archivos `.key` y `certs/` están en `.gitignore` para evitar exponer claves privadas.
- **Rotación**: Para producción, se deben rotar periódicamente los certificados (especialmente `ca.key`, `server.key` y `client.key`).
- **Protección de claves**: Las claves privadas (`*.key`) deben tener permisos restringidos (lectura solo para el usuario del contenedor).
- **Revocación**: Aunque no hay CRL en el ejemplo, en un despliegue real se debe implementar un mecanismo de revocación (OCSP o lista negra).

---

## 📌 Resumen visual

```
CA Raíz (ca.crt / ca.key)
├── Emite server.crt → Envoy (PEP)
├── Emite client.crt → soc_admin, operatore_ancona, etc.
├── Emite device.crt → D-001, D-002, D-SOC
└── Emite mongodb.crt → MongoDB
```

Esta jerarquía permite **confianza cero**: ningún servicio o cliente confía en nadie sin un certificado válido firmado por la CA raíz. Todo el tráfico está cifrado y autenticado bidireccionalmente, cumpliendo con el mandato **"Never Trust, Always Verify"** de NIST SP 800-207.
