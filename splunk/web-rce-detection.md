# Use Case: Detección de ejecución remota de código (RCE) en servidores web

---

## 1. Contexto del ataque

Un ataque de **Remote Code Execution (RCE)** en aplicaciones web permite a un atacante ejecutar comandos en el servidor objetivo a través de una vulnerabilidad.

Este tipo de ataque suele derivar en:

* Web shells
* Reverse shells
* Compromiso total del servidor

Ejemplos reales:

* Drupalgeddon (Drupal)
* File upload vulnerable
* Command injection

---

## 2. Objetivo de detección

Detectar:

* Ejecución de procesos del sistema (bash, sh, cmd, powershell)
* Lanzados desde servicios web (Apache, Nginx, IIS)
* Indicando explotación de vulnerabilidad

---

## 3. Fuentes de logs

* Sysmon (Windows)
* Auditd / Syslog (Linux)
* Logs de servidor web (Apache/Nginx/IIS)

Eventos clave:

* Creación de proceso
* Actividad HTTP

---

## 4. Query en Splunk (proceso sospechoso desde servicio web)

```spl id="webrceq1"
index=sysmon EventCode=1
| eval is_web_parent=if(match(parent_process_name,"(apache|httpd|nginx|iis|w3wp)"),1,0)
| eval is_shell=if(match(process_name,"(bash|sh|cmd.exe|powershell.exe)"),1,0)
| stats count by host, parent_process_name, process_name, user
| where is_web_parent=1 AND is_shell=1
```

---

## 5. Explicación de la query

1. Filtra eventos de creación de proceso

2. Identifica procesos lanzados por servicios web:

   * apache / httpd
   * nginx
   * IIS / w3wp

3. Detecta ejecución de shells:

   * bash
   * sh
   * cmd
   * powershell

4. Correlaciona ambos comportamientos

---

## 6. Qué detecta

* Ejecución de comandos desde aplicaciones web
* Explotación de vulnerabilidades RCE
* Web shells activas
* Post-explotación inicial

---

## 7. Ejemplo de comportamiento malicioso

```text id="webrceex1"
Parent process: apache2
Process: /bin/bash
Usuario: www-data
```

👉 Esto NO es comportamiento normal

---

## 8. Diferenciación: normal vs malicioso

### Comportamiento legítimo

* Apache sirviendo contenido web
* Sin ejecución de shells

---

### Comportamiento sospechoso

* apache → bash
* nginx → sh
* w3wp → powershell

👉 Indicador directo de explotación

---

## 9. Posibles falsos positivos

* Scripts de administración automatizados
* Herramientas de despliegue
* tareas programadas mal configuradas

👉 Validar contexto y frecuencia

---

## 10. Cómo investigar (playbook SOC)

1. Identificar proceso ejecutado

2. Revisar proceso padre (web server)

3. Analizar logs HTTP previos:

   * parámetros sospechosos
   * uploads

4. Correlacionar con:

   * conexiones salientes (reverse shell)
   * creación de archivos sospechosos

5. Determinar:

   * origen del ataque
   * persistencia

---

## 11. Mitigación

* Validación de inputs
* Parcheo de aplicaciones web
* Deshabilitar ejecución de comandos desde web
* Implementar WAF
* Monitorización activa de procesos

---

## 12. MITRE ATT&CK

* T1190 – Exploit Public-Facing Application
* T1059 – Command Execution
* T1505 – Server Software Component
* T1105 – Ingress Tool Transfer

---

## 13. Relación con labs

Este comportamiento aparece en:

* Drupal
* Nibbles
* Knife
* cualquier explotación web

---

## 14. Conclusión

La ejecución de comandos desde un servicio web es uno de los indicadores más claros de compromiso.

La correlación entre procesos y servicios permite detectar RCE de forma fiable.
