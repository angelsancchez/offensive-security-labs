# Informe de Seguridad - Evaluación de Host "Optimum"

## 1. Resumen Ejecutivo

Se ha realizado una evaluación de seguridad sobre el host objetivo "Optimum", identificado en un entorno controlado de laboratorio.

Durante el análisis se ha identificado una vulnerabilidad crítica en el servicio HTTP File Server (HFS) que permite la ejecución remota de código (RCE) sin autenticación. Esta vulnerabilidad ha sido explotada con éxito, permitiendo el acceso inicial al sistema.

Posteriormente, se ha llevado a cabo una escalada de privilegios mediante la explotación de una vulnerabilidad local en el sistema Windows, obteniendo acceso con privilegios de administrador.

### Impacto
- Compromiso total del sistema
- Ejecución remota de código sin autenticación
- Escalada de privilegios a nivel SYSTEM

### Nivel de riesgo: **CRÍTICO**

---

## 2. Alcance

- Objetivo: Máquina "Optimum"
- Tipo de evaluación: Caja única (Black Box)
- Metodología: Enumeración → Explotación → Escalada de privilegios

---

## 3. Enumeración

### 3.1 Escaneo de Puertos

Se realizó un escaneo inicial con Nmap:

```bash
nmap -sC -sV -p- <IP>
