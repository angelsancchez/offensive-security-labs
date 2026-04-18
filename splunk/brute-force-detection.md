# Use Case: Detección de ataques de fuerza bruta en Windows (correlación de eventos)

---

## 1. Contexto del ataque

Un ataque de **fuerza bruta** consiste en múltiples intentos fallidos de autenticación con el objetivo de adivinar credenciales válidas.

En entornos Windows, este comportamiento genera eventos repetidos de fallo de login, que pueden terminar en un acceso exitoso si el atacante acierta la contraseña.

---

## 2. Objetivo de detección

Detectar:

* Múltiples intentos fallidos de login (**Event ID 4625**)
* Seguidos de un login exitoso (**Event ID 4624**)
* Desde la misma IP o contra la misma cuenta

---

## 3. Fuente de logs

* Windows Security Logs

Eventos clave:

* **4625** → Login fallido
* **4624** → Login exitoso

---

## 4. Query en Splunk (correlada)

```spl id="bfq1"
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval outcome=if(EventCode=4625,"fail","success")
| stats count(eval(outcome="fail")) as failed_attempts
        count(eval(outcome="success")) as successful_logins
        values(outcome) as outcomes
        by Account_Name, src_ip
| where failed_attempts > 5 AND successful_logins > 0
| sort - failed_attempts
```

---

## 5. Explicación de la query

1. Filtra eventos de autenticación (4625 y 4624)
2. Clasifica:

   * `fail` → intentos fallidos
   * `success` → login exitoso
3. Agrupa por:

   * Usuario
   * IP origen
4. Cuenta:

   * número de fallos
   * número de éxitos
5. Detecta:

   * múltiples fallos + éxito posterior

---

## 6. Qué detecta

* Ataques de fuerza bruta exitosos
* Password spraying
* Intentos de acceso repetidos

---

## 7. Ejemplo de comportamiento malicioso

```text id="bfex1"
Usuario: administrator
IP: 192.168.1.100
Intentos fallidos: 25
Login exitoso: 1
```

👉 Patrón típico de compromiso

---

## 8. Diferenciación: normal vs malicioso

### Comportamiento legítimo

* 1–2 fallos ocasionales
* Usuarios olvidando contraseña
* Sin patrón repetitivo

---

### Comportamiento sospechoso

* Muchos intentos en poco tiempo
* Múltiples cuentas atacadas desde misma IP
* Login exitoso tras múltiples fallos

---

## 9. Posibles falsos positivos

* Usuarios que olvidan contraseñas repetidamente
* Scripts de login automatizados
* Sistemas mal configurados

👉 Clave: contexto + frecuencia + volumen

---

## 10. Cómo investigar (playbook SOC)

1. Identificar usuario afectado
2. Revisar IP origen
3. Ver si la IP aparece en múltiples cuentas
4. Correlacionar con:

   * Event ID 4672 (privilegios elevados)
   * actividad posterior del usuario
5. Evaluar:

   * ¿hubo movimiento lateral?
   * ¿acceso a recursos críticos?

---

## 11. Mitigación

* Implementar políticas de bloqueo de cuenta
* Activar MFA
* Monitorizar intentos de login
* Restringir accesos por IP
* Implementar alertas en SIEM

---

## 12. MITRE ATT&CK

* T1110 – Brute Force
* T1078 – Valid Accounts

---

## 13. Relación con labs

Este comportamiento se puede observar en:

* Entornos Windows comprometidos
* Escenarios de acceso inicial

---

## 14. Conclusión

La correlación de eventos 4625 y 4624 permite detectar ataques de fuerza bruta que resultan en acceso exitoso.

Sin correlación, este tipo de ataques puede pasar desapercibido.

