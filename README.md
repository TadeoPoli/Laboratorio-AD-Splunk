# Active Directory Security Monitoring & Threat Detection with Splunk

## Descripción

Laboratorio virtual de **monitoreo de seguridad, detección y correlación de eventos**, orientado a prácticas **SOC / Blue Team**. Utiliza un dominio Active Directory como infraestructura de prueba para observar autenticaciones, administración de cuentas y grupos, y actividad de una estación Windows.

**Splunk Enterprise**, alojado en Kali Purple, centraliza los registros enviados desde el controlador de dominio y el endpoint. Los eventos de Windows Security aportan información de autenticación y cambios administrativos; **Sysmon** permite examinar la creación de procesos, y **PowerShell Script Block Logging** registra contenido de bloques de scripts.

El proyecto comprende **dos fases**: implementación y validación de la recopilación de eventos, seguida del desarrollo de consultas SPL y seis alertas programadas. Las pruebas abarcan autenticaciones fallidas, cambios de pertenencia a grupos, reconocimiento local, comandos PowerShell codificados, creación de tareas programadas y correlación temporal.

Es un **entorno virtual controlado**, no una infraestructura empresarial real. Las simulaciones utilizaron instrucciones inofensivas y sus resultados se presentan junto con las limitaciones de la evidencia y de las detecciones.

---

## Objetivos

- Implementar un dominio Active Directory con un controlador y una estación de trabajo.
- Configurar auditoría avanzada en DC01 y centralizar registros Windows mediante Splunk Universal Forwarder.
- Incorporar telemetría de Sysmon y PowerShell Script Block Logging desde WS01.
- Analizar Event ID y desarrollar consultas SPL con extracción y normalización de campos.
- Crear seis alertas programadas y validar sus activaciones y resultados en Splunk.
- Correlacionar diferentes fuentes por equipo y ventana temporal, documentando el alcance de las conclusiones.

---

## Arquitectura del laboratorio

![Arquitectura del laboratorio](<Image/Arquitectura del laboratorio de seguridad.png>)

**DC01** proporciona Active Directory y DNS para `corp.local`. **WS01** es la estación Windows incorporada al dominio. Ambos equipos envían eventos mediante **Splunk Universal Forwarder** al receptor **TCP 9997** de **Kali Purple**, donde Splunk Enterprise los almacena en el índice **`windows`**.

Se recopilan Application, Security y System de ambos equipos, más los canales operativos de Sysmon y PowerShell de WS01. La pertenencia de WS01 al dominio y el envío de registros son relaciones diferentes: cada agente envía sus eventos directamente al servidor Splunk.

---

## Índice de navegación

- [Descripción](#descripción)
- [Objetivos](#objetivos)
- [Arquitectura del laboratorio](#arquitectura-del-laboratorio)
- [Infraestructura del laboratorio](#infraestructura-del-laboratorio)
- [Herramientas utilizadas](#herramientas-utilizadas)
- [Configuración del entorno — Documentación complementaria](#configuración-del-entorno--documentación-complementaria)
- [Fase 1 — Implementación de infraestructura y centralización de eventos](#fase-1--implementación-de-infraestructura-y-centralización-de-eventos)
- [Fase 2 — Detección y correlación de eventos de seguridad](#fase-2--detección-y-correlación-de-eventos-de-seguridad)
- [Conocimientos adquiridos](#conocimientos-adquiridos)

---

## Infraestructura del laboratorio

| Equipo | Sistema operativo | Dirección IP | Función |
| :--- | :--- | :--- | :--- |
| **DC01** | Windows Server 2022 | `192.168.20.5` | Controlador de dominio, AD DS y DNS |
| **WS01** | Windows 10 | `192.168.20.132` | Endpoint del dominio |
| **Kali Purple** | Kali Purple 2026.3 | `192.168.20.134` | Servidor Splunk Enterprise |

| Parámetro | Configuración |
| :--- | :--- |
| Virtualización | VMware Workstation Pro |
| Red privada | Host-only, `192.168.20.0/24` |
| Dominio | `corp.local` |
| Receptor Splunk | `192.168.20.134:9997`, TCP |
| Índice de eventos | `windows` |

Las direcciones identifican los equipos utilizados; no implican que todas las máquinas recibieran su IP mediante el mismo método.

---

## Herramientas utilizadas

| Tecnología | Función en el laboratorio |
| :--- | :--- |
| **VMware Workstation Pro** | Virtualización de los tres equipos y conexión mediante una red privada Host-only. |
| **Windows Server 2022** | Sistema operativo de DC01 y origen de registros de seguridad del dominio. |
| **Active Directory Domain Services** | Gestión del dominio, las identidades y las cuentas de equipo. |
| **Windows 10** | Sistema operativo de WS01, origen de telemetría y equipo de las simulaciones locales. |
| **Kali Purple** | Sistema que aloja el servidor central de Splunk Enterprise. |
| **Splunk Enterprise** | Indexación, búsqueda de eventos y ejecución de alertas programadas; consulta mediante Splunk Web. |
| **Splunk Universal Forwarder** | Recopilación y envío de los registros de DC01 y WS01. |
| **Sysmon** | Telemetría del sistema según su configuración; eventos de creación de procesos utilizados en las pruebas. |

---

## Configuración del entorno — Documentación complementaria

La guía de preparación explica cómo reproducir una infraestructura equivalente: creación de la red Host-only, preparación de DC01 con Active Directory y DNS, incorporación de WS01 al dominio y conectividad de Kali Purple. Incluye comprobaciones básicas y uso temporal de NAT, distinguiendo los parámetros confirmados de las instrucciones recomendadas.

➡️ [Consultar guía de configuración del entorno](Docs/Configuraciones.md)

---

## Fase 1 — Implementación de infraestructura y centralización de eventos

La primera fase prepara la recopilación de registros y verifica su recepción en Splunk Enterprise.

- Instalación de Splunk Enterprise en Kali Purple.
- Configuración de Universal Forwarder en DC01 y WS01.
- Configuración de auditoría avanzada en DC01.
- Instalación de Sysmon y habilitación de PowerShell Script Block Logging en WS01.
- Comprobación de la recepción de eventos desde ambos equipos.

➡️ **[Ver documentación completa de la Fase 1](Docs/Fase1.md)**

---

## Fase 2 — Detección y correlación de eventos de seguridad

La segunda fase utiliza la telemetría centralizada para desarrollar y validar detecciones y alertas programadas mediante seis simulaciones controladas.

1. Autenticaciones fallidas en Active Directory.
2. Cambios en cuentas y grupos de Active Directory.
3. Reconocimiento mediante PowerShell.
4. Ejecución de PowerShell con comandos codificados.
5. Creación de tareas programadas.
6. Correlación de un escenario de múltiples etapas.

La documentación completa reúne los procedimientos, alertas, evidencias y resultados de las seis pruebas.

➡️ **[Ver documentación completa de la Fase 2](Docs/Fase2.md)**

---

## Conocimientos adquiridos

El proyecto permitió desarrollar práctica en:

- **Active Directory y Windows:** administración básica del dominio, cuentas y grupos; auditoría de seguridad mediante GPO y configuración local cuando corresponde.
- **Recopilación de registros:** configuración de Universal Forwarder y centralización de fuentes Windows, Sysmon y PowerShell Script Block Logging.
- **Análisis de eventos:** identificación de Event ID, distinción entre fuentes y sourcetypes, inspección de mensajes y eventos XML.
- **Splunk y SPL:** búsquedas, extracción mediante `rex`, normalización de identificadores y agregación de resultados.
- **Alertamiento:** configuración de programación, ventanas temporales, umbrales y supresión; validación mediante historiales y resultados.
- **Correlación temporal:** combinación de diferentes fuentes por host, interpretación de ventanas superpuestas y separación entre coincidencia y causalidad.
- **Criterio analítico y documentación:** contraste entre comandos, capturas y registros escritos; interpretación contextual de MITRE ATT&CK y comunicación de falsos positivos y limitaciones.

Las dos fases documentan el recorrido desde la recopilación de eventos hasta la validación de detecciones y correlaciones en un entorno controlado.
