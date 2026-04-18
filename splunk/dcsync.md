# Use Case: Detección de ataque DCSync en Active Directory

---

## 1. Contexto del ataque

El ataque **DCSync** permite a un atacante simular el comportamiento de un Controlador de Dominio y solicitar la replicación de credenciales desde Active Directory.

Mediante este ataque, el adversario puede obtener hashes NTLM de cuentas críticas, incluyendo el Administrador del dominio, sin necesidad de acceso directo al controlador de dominio.

Este ataque se basa en permisos de replicación:

* DS-Replication-Get-Changes
* DS-Replication-Get-Changes-All

---

## 2. Objetivo de detección

Detectar accesos no autorizados a funciones de replicación de Active Directory que puedan indicar un intento de extracción de credenciales (DCSync).

---

## 3. Fuente de logs

* Windows Security Logs
* Event ID: **4662 (Object Access)**

---

## 4. Query en Splunk

```spl id="dcsyncq1"
index=wineventlog EventCode=4662
| search Object_Type="domainDNS"
| search Properties="Replicating Directory Changes"
OR Properties="Replicating Directory Changes All"
| stats count by Account_Name, src_ip
| sort - count
```

---

## 5. Explicación de la query

1. Filtra eventos 4662 relacionados con acceso a objetos del dominio
2. Busca propiedades asociadas a replicación de AD
3. Agrupa por:

   * Cuenta (Account_Name)
   * IP origen (src_ip)
4. Permite identificar qué cuentas están solicitando replicación

---

## 6. Qué detecta

* Uso de permisos de replicación de Active Directory
* Posible ejecución de herramientas como:

  * Mimikatz (`lsadump::dcsync`)
  * Impacket (`secretsdump.py`)

---

## 7. Ejemplo de comportamiento malicioso

```text id="dcsyncex1"
Usuario: svc_backup
IP origen: 10.10.10.55
Acción: Solicitud de replicación de dominio
Frecuencia: múltiples eventos en pocos segundos
```

👉 Este comportamiento es altamente sospechoso si no proviene de un DC

---

## 8. Diferenciación: normal vs malicioso

### Comportamiento legítimo

* Ejecutado por Controladores de Dominio
* Procesos internos de replicación
* IPs conocidas de infraestructura

---

### Comportamiento sospechoso

* Ejecutado por cuentas de usuario normales
* Desde hosts que NO son DC
* Actividad puntual fuera de patrones habituales

---

## 9. Posibles falsos positivos

* Herramientas de backup de Active Directory
* Software de sincronización autorizado
* Auditorías internas

👉 Clave: validar origen + contexto

---

## 10. Cómo investigar (playbook SOC)

1. Identificar la cuenta utilizada
2. Validar si tiene permisos de replicación
3. Revisar IP origen:

   * ¿es un DC?
   * ¿es un endpoint?
4. Correlacionar con:

   * Event ID 4624 (logon)
   * Event ID 4672 (privilegios elevados)
5. Buscar actividad posterior:

   * Pass-the-Hash
   * acceso lateral

---

## 11. Mitigación

* Restringir permisos de replicación
* Revisar ACL en Active Directory
* Aplicar principio de mínimo privilegio
* Monitorizar eventos 4662
* Implementar alertas en SIEM

---

## 12. MITRE ATT&CK

* T1003.006 – DCSync
* T1003 – OS Credential Dumping
* T1550 – Use Alternate Authentication Material

---

## 13. Relación con labs

Este comportamiento se observa en:

* Forest
* Sauna

---

## 14. Conclusión

DCSync es uno de los ataques más críticos en entornos Active Directory, ya que permite el compromiso total del dominio sin necesidad de acceso directo a los controladores.

Una detección adecuada basada en eventos 4662 permite identificar este comportamiento en fases tempranas.
