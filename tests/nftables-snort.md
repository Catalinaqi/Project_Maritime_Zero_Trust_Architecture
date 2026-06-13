Para diseñar correctamente la estrategia de defensa perimetral e interna (ZTA)
en este entorno marítimo, es fundamental entender qué "ve" cada herramienta
y en qué nivel del modelo de seguridad opera.

---

### 1. ¿En qué deberían basarse las reglas de `nftables` y `snort3`? ¿Son ciegos al negocio?

#### **`nftables` (Capa de Red y Transporte - Capas 3 y 4)**

* **En qué se basan sus reglas:** 

* Se basan estrictamente en **atributos de red estáticos**: 
    - Direcciones IP de origen y destino, 
    - protocolos (TCP, UDP, ICMP) y 
    - puertos.
  
* **¿Es ciego al negocio?:** 

**Sí, es 100% ciego al negocio.** 
A `nftables` no le importa qué datos viajen dentro del paquete, 
ni qué rol tiene el usuario en la aplicación (si es la Capitana o el Intruso). 
Su única misión es la **microsegmentación**.

* *Ejemplo de regla:* "La IP de `api_backend` (`172.20.3.20`) puede hablar con la IP de `db_primary` (`172.20.3.5`) por el puerto `27017`. 
* Cualquier otra IP que intente tocar el puerto `27017` se descarta (`DROP`)."



#### **`snort3` (Capa de Aplicación y Contenido - Capas 4 a 7)**

* **En qué se basan sus reglas:** Se basan en 
**firmas de ataques, anomalías de protocolos y patrones de texto (payload)** dentro de los paquetes de datos.

* **¿Es ciego al negocio?:** 

**Por defecto, sí; pero tú puedes hacer que no lo sea.** 
Si el tráfico de tu red viaja cifrado bajo TLS estricto (como lo tienes configurado en MongoDB), 
Snort se vuelve "ciego" al contenido del negocio porque solo ve datos binarios ilegibles. 
Solo podría alertar si ve anomalías en el canal de red (ej. un escaneo de puertos masivo o inundación de paquetes).
Sin embargo, si colocas a Snort a escuchar en un punto de la red donde el tráfico está en texto claro 
(por ejemplo, antes de que el Envoy Gateway cifre el paquete, o analizando los logs en tiempo real), 
**deja de ser ciego al negocio**. Puedes escribir reglas personalizadas de Snort que busquen palabras clave del negocio marítimo o de base de datos.

* *Ejemplo de regla:* `alert tcp any any -> any 27017 (msg:"Posible Inyección en DB"; content:"$where"; sid:1000001;)` 
* (Aquí Snort busca si alguien intenta usar el comando peligroso `$where` de MongoDB).



---

### 2. ¿Las pruebas se hacen de acuerdo a los clientes o a los devices?

**Se hacen de acuerdo a ambos, pero en diferentes herramientas.** En una arquitectura Zero Trust, cada componente valida una parte de la política:

1. **Las pruebas de `nftables` se basan en la RED (Subredes de los contenedores):**
   Tus pruebas deben verificar que la segmentación de red funcione. Debes probar que el contenedor `client_intruso` 
   (ubicado en la red pública o de atacantes) sufra un bloqueo inmediato de 
   red si intenta conectarse directamente a la IP de la base de datos o de la API sin pasar por el `pep_gateway`.
2. **Las pruebas de `snort3` se basan en el COMPORTAMIENTO (Payload):**
   Tus pruebas deben simular acciones maliciosas usando los clientes. 
   Por ejemplo, ejecutas un script desde el cliente `operatore_ancona` que 
   envíe un comando corrupto o un ataque conocido de denegación de servicio. 
   La prueba tiene éxito si Snort detecta la firma del ataque y genera la 
   alerta para Splunk.
3. **La identidad del "Cliente" y del "Device" la validan Envoy y OPA:**
   El cortafuegos (`nftables`) y el IDS (`snort3`) cuidan las autopistas y el contrabando de la red. Pero quien realmente 
   verifica si el certificado pertenece a `capitano_claudia` o si el 
   dispositivo `D-001` tiene permisos para autorizar una ruta de navegación es el **`pep_gateway` (Envoy)** consultando al **`pdp_engine` (OPA)**.

---
