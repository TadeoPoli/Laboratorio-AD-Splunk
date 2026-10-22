[⬅️ Volver al README principal](../README.md)

# Configuraciones del entorno virtual

## Introducción

Esta guía complementa la [Fase 1 — Implementación y centralización de eventos](Fase1.md) y la [Fase 2 — Detección y correlación](Fase2.md). Explica cómo preparar una infraestructura equivalente para reproducir sus procedimientos. El proyecto consta de esas dos fases; este documento es una referencia de preparación.

Los equipos, direcciones y dominio siguientes corresponden al laboratorio. Los pasos de instalación y las comprobaciones propuestas son instrucciones de reproducción adaptadas de los materiales de referencia, no un registro de ejecución ni evidencias adicionales de la implementación.

| Equipo | Sistema operativo | Dirección IP | Función |
| --- | --- | --- | --- |
| DC01 | Windows Server 2022 | `192.168.20.5` | Controlador de dominio, AD DS y DNS |
| WS01 | Windows 10 | `192.168.20.132` | Endpoint unido a `corp.local` |
| Kali Purple | Kali Purple Linux | `192.168.20.134` | Servidor Splunk Enterprise |

La red privada es `192.168.20.0/24`, con máscara `255.255.255.0`, en VMware Workstation Pro mediante Host-only. Solo se necesita una estación Windows cliente.

## Requisitos previos

- VMware Workstation Pro instalado y permisos administrativos para configurar sus redes virtuales.
- Imagen de instalación de Windows Server 2022. La Fase 1 identifica Standard Evaluation; seleccionar **Desktop Experience / Experiencia de escritorio** para disponer de interfaz gráfica.
- Imagen de Windows 10 y licencia o modalidad de evaluación aplicable. Para reproducir la unión a Active Directory, utilizar una edición compatible, por ejemplo **Pro**; la edición exacta de WS01 no está acreditada en las fases.
- Imagen de instalación de Kali Purple obtenida de su distribución oficial. La Fase 1 registra Kali Purple 2026.3.
- Recursos del anfitrión suficientes para ejecutar las tres máquinas. Dimensionar memoria, CPU y disco según los sistemas elegidos y su documentación; no se conserva una asignación de hardware verificada del laboratorio.

Obtener las imágenes desde los canales oficiales de Microsoft y Kali, respetando sus condiciones de uso. Las ediciones compatibles con la unión a dominio se detallan en la [documentación de Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/join-computer-to-domain).

## Creación de la red privada

Host-only conecta las máquinas entre sí y, si se habilita el adaptador virtual correspondiente, con el anfitrión. No proporciona por sí sola salida a Internet. NAT permite utilizar la conectividad del anfitrión. Estas funciones se describen en la [referencia de redes de VMware](https://knowledge.broadcom.com/external/article?legacyId=1006480).

1. En VMware Workstation Pro, abrir **Edit → Virtual Network Editor → Change Settings**.
2. Seleccionar **Add Network** y un identificador VMnet libre. Anotar el elegido: el identificador utilizado originalmente no está confirmado.
3. Seleccionar **Host-only** y establecer **Subnet IP: `192.168.20.0`** y **Subnet Mask: `255.255.255.0`**. Comprobar que no se superponga con otra red del anfitrión o de su VPN.
4. Para permitir acceso desde el anfitrión, marcar **Connect a host virtual adapter to this network**. Verificar que su dirección no coincida con ninguna de las tres máquinas.
5. Para una reproducción con las direcciones manuales propuestas en esta guía, desmarcar **Use local DHCP service to distribute IP addresses to VMs**. Si se elige DHCP para algún cliente, habilitarlo y revisar su rango para evitar solapamientos con las direcciones manuales; no se documenta un rango DHCP original.
6. Aplicar los cambios. En cada VM, abrir **VM → Settings → Network Adapter**, elegir **Custom: Specific virtual network** y seleccionar la misma VMnet. Marcar **Connected** y **Connect at power on** cuando corresponda.

Para esta red privada sin router, dejar vacía la puerta de enlace de las máquinas. El adaptador Host-only del anfitrión no constituye automáticamente un gateway. Esta es una instrucción de reproducción, no la confirmación de un valor histórico.

DC01 debe conservar una dirección estable. En WS01 y Kali Purple se conocen las IP utilizadas, pero no se ha confirmado si se obtuvieron mediante DHCP o configuración manual. La asignación manual que se propone a continuación permite reproducir esos valores sin atribuir ese método a la implementación original.

## Preparación de DC01

### Instalación, nombre y dirección IP

1. Crear una VM desde **File → New Virtual Machine**, asociar la ISO de Windows Server 2022 y seleccionar el perfil de sistema invitado correspondiente. El nombre de la VM en VMware no cambia el nombre interno de Windows.
2. Arrancar desde la ISO, seleccionar **Standard Evaluation con Experiencia de escritorio** y realizar la instalación personalizada sobre el disco virtual destinado a esta VM.
3. Definir una contraseña propia y robusta para el administrador local e iniciar sesión. VMware Tools puede instalarse desde **VM → Install VMware Tools** para la integración del invitado; reiniciar si se solicita.
4. Abrir **Administrador del servidor → Servidor local → Nombre de equipo**, cambiar el nombre a **DC01** y reiniciar antes de instalar el dominio.
5. Conectar la VM a la red Host-only creada. Abrir `ncpa.cpl` desde **Ejecutar**, acceder a las propiedades del adaptador activo y a **Protocolo de Internet versión 4 (TCP/IPv4)**.
6. Configurar IP estática `192.168.20.5`, máscara `255.255.255.0` y sin gateway para esta red aislada. Para esta reproducción con un único DC y DNS, configurar el DNS preferido hacia su propia IP, `192.168.20.5`. Resolverá el dominio cuando se haya instalado y configurado el servicio DNS.

### AD DS, bosque y DNS

1. En **Administrador del servidor → Administrar → Agregar roles y características**, seleccionar instalación basada en roles, el servidor local y **Servicios de dominio de Active Directory**. Aceptar las herramientas de administración requeridas e instalar.
2. Al finalizar, seleccionar **Promover este servidor a controlador de dominio**. Instalar el rol por sí solo no crea el dominio.
3. Elegir **Agregar un nuevo bosque** e introducir `corp.local` como nombre del dominio raíz.
4. En las opciones del controlador, mantener **Servidor DNS** y **Catálogo global** para este primer DC. Definir una contraseña robusta y propia para **DSRM**, destinada a recuperación del directorio.
5. Revisar los niveles funcionales ofrecidos por el asistente para Windows Server 2022, sin asumir que coinciden con el nombre del sistema operativo. Para una reproducción nueva, conservar los valores compatibles propuestos; no se documentan los niveles originales.
6. Revisar DNS, comprobar el nombre NetBIOS **CORP** y conservar las rutas predeterminadas de base de datos, registros y SYSVOL para esta reproducción. No crear una delegación hacia una zona superior inexistente para este bosque privado.
7. Ejecutar la comprobación de requisitos, resolver los errores bloqueantes e instalar. Tras el reinicio, iniciar sesión con la cuenta administrativa del dominio.

El asistente y sus opciones están descritos en la [guía de instalación de AD DS de Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-).

DNS permite localizar DC01 y los servicios de Active Directory mediante registros del dominio, incluidos registros SRV. En **Herramientas → DNS**, comprobar la zona `corp.local` y los registros de localización del controlador. Que un equipo responda por IP no demuestra que estos registros se resuelvan.

## Preparación de WS01

1. Crear una única VM Windows 10 desde su ISO, completar la instalación y disponer de una cuenta administradora local para la preparación.
2. Cambiar el nombre interno a **WS01** desde las propiedades del sistema y reiniciar.
3. Conectar su adaptador a la misma VMnet Host-only. En `ncpa.cpl`, abrir las propiedades IPv4. Para la reproducción manual propuesta, usar `192.168.20.132`, máscara `255.255.255.0` y sin gateway.
4. Configurar el **DNS preferido en `192.168.20.5`**. No sustituirlo por un DNS público para buscar `corp.local`. Si se usa DHCP para la dirección del cliente, comprobar igualmente qué DNS utiliza.
5. Con DC01 encendido, verificar la conectividad y la resolución del dominio según el apartado de comprobaciones.
6. Abrir `sysdm.cpl` desde **Ejecutar**, ir a **Nombre de equipo → Cambiar → Miembro de: Dominio**, introducir `corp.local` y proporcionar una cuenta autorizada para unir equipos. Reiniciar tras la confirmación de unión.

La unión incorpora una **cuenta de equipo** al dominio; no convierte la cuenta utilizada para unirlo en su único usuario ni otorga por sí sola privilegios administrativos a los usuarios del dominio.

Para preparar una cuenta de uso cotidiano, abrir en DC01 **Herramientas → Usuarios y equipos de Active Directory**, seleccionar el contenedor adecuado y crear un usuario, por ejemplo `empleado1`, con contraseña propia y los permisos necesarios. Esa identidad aparece en las pruebas del laboratorio. No es necesario concederle administración del dominio para iniciar sesión en WS01.

En WS01, seleccionar **Otro usuario** e iniciar sesión como `CORP\empleado1` o `empleado1@corp.local`. La cuenta local y la cuenta de dominio son identidades distintas. Comprobar también en las propiedades del sistema la pertenencia a `corp.local` y en Active Directory la existencia del equipo WS01.

Si no se encuentra el dominio, revisar primero la VMnet seleccionada, la disponibilidad de DC01, el DNS del cliente y los registros del dominio. La detección de redes de Windows no sustituye estas comprobaciones. Revisar las reglas de firewall necesarias sin desactivarlo globalmente.

## Preparación de Kali Purple

1. Crear la VM con la imagen de Kali Purple, completar su instalador y conectar el adaptador a la misma VMnet Host-only.
2. En el administrador gráfico de conexiones de red, seleccionar la conexión cableada activa y abrir sus ajustes IPv4. Su nombre depende de la instalación.
3. Para reproducir la dirección utilizada, seleccionar **Manual**, introducir `192.168.20.134/24` y dejar el gateway vacío. Como opción de reproducción, utilizar `192.168.20.5` para resolver nombres del dominio; esto no acredita cuál era el DNS original de Kali Purple.
4. Guardar y volver a activar la conexión. Comprobar la dirección con los comandos del apartado siguiente.

Kali Purple aloja Splunk Enterprise y recibe eventos de los Universal Forwarder de DC01 y WS01 en **TCP 9997**. Su dirección debe permanecer estable para mantener el destino configurado en los agentes. Su función no requiere unirlo al dominio.

Continuar con la [instalación y configuración de Splunk en la Fase 1](Fase1.md#1-instalación-y-configuración-de-splunk-enterprise-en-kali-purple), donde se documentan el receptor, Splunk Web y el índice `windows`.

## Comprobaciones de conectividad

### Comandos recomendados para reproducir el entorno

Los comandos siguientes son comprobaciones propuestas. No se presentan como ejecuciones históricas ni se incluyen salidas inventadas.

En PowerShell de **WS01**, revisar el nombre, la configuración IPv4, DNS y la pertenencia al dominio:

```powershell
hostname
ipconfig /all
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, PartOfDomain
whoami
```

Contrastar la dirección con `192.168.20.132` y el DNS con `192.168.20.5`. Después de la unión, comprobar que el dominio sea `corp.local` y que `PartOfDomain` sea verdadero. `whoami` identifica la sesión actual; no sustituye la comprobación de pertenencia del equipo.

Desde **WS01**, probar alcance IP y consultar explícitamente el DNS de DC01:

```powershell
ping 192.168.20.5
Resolve-DnsName DC01.corp.local -Server 192.168.20.5
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.corp.local -Type SRV -Server 192.168.20.5
```

La consulta de nombre debe permitir identificar la dirección de DC01 y la consulta SRV, los servicios de localización del controlador. Estas son condiciones esperadas para la reproducción. Un fallo de `ping` puede deberse al filtrado ICMP; no demuestra por sí solo que AD DS o DNS estén inaccesibles.

En **Kali Purple**, consultar las direcciones y rutas, y probar alcance IP hacia DC01:

```bash
ip -br address
ip route
ping -c 4 192.168.20.5
```

Una vez habilitado el receptor de Splunk, desde **DC01 o WS01** puede comprobarse el puerto:

```powershell
Test-NetConnection 192.168.20.134 -Port 9997
```

Un resultado TCP satisfactorio demuestra acceso al puerto, no recepción efectiva de eventos. Esa recepción se comprueba con las búsquedas SPL de la Fase 1.

### Comprobaciones documentadas en el laboratorio

- La **Fase 1, sección 2.4**, registra `Test-NetConnection 192.168.20.134 -Port 9997` desde **DC01**, con `TcpTestSucceeded : True`. La comprobación proviene del registro de implementación, sin captura de esa salida.
- La **Fase 1, sección 4.3**, aclara que no se registró una prueba TCP independiente desde **WS01**. Ejecutar el comando anterior allí sería una comprobación nueva.
- Las fases documentan recepción de eventos de ambos equipos en Splunk y uso de cuentas del dominio. No se dispone de capturas de la creación de la red virtual ni de toda la secuencia de instalación y unión al dominio.

## Uso temporal de NAT

Para descargar herramientas o actualizaciones, puede conectarse temporalmente una VM a NAT. El siguiente procedimiento está pensado para Kali Purple o WS01 durante mantenimiento, fuera de las pruebas:

1. Anotar la VMnet privada y los valores actuales de IP, máscara, DNS y gateway.
2. En **VM → Settings → Network Adapter**, cambiar de **Custom** a **NAT**, manteniendo el adaptador conectado.
3. En el invitado, cambiar IPv4 y DNS a obtención automática si la red NAT de VMware dispone de DHCP. En Windows se hace desde las propiedades IPv4; en Kali Purple, desde el perfil de conexión. Reactivar la conexión y comprobar los nuevos valores.
4. Realizar las descargas. No reutilizar las direcciones de Host-only ni inventar un gateway para NAT: son redes distintas.
5. Volver a **Custom** y seleccionar la VMnet privada original. Restaurar su configuración IP y DNS; en WS01, el DNS debe volver a DC01. Repetir las comprobaciones antes de continuar el laboratorio.

Durante el cambio, WS01 puede perder acceso a DC01 y Kali Purple deja de estar disponible para los agentes en su dirección privada. No esperar continuidad de autenticación o recepción de eventos mientras los equipos estén separados en redes distintas.

Para **DC01 ya promovido**, preferir descargar los instaladores en el anfitrión o en Kali Purple y transferirlos por un medio controlado, conservando su IP y DNS. No aplicar automáticamente el cambio a DHCP de un cliente al controlador de dominio. Si se utiliza NAT antes de promocionarlo, restaurar la red privada y su configuración estática antes de instalar el dominio.

Esta guía no presupone enrutamiento entre NAT y Host-only ni una configuración de reenviadores DNS. La resolución de nombres externos desde la red privada requeriría una configuración adicional que no está documentada.


---

[⬅️ Volver al README principal](../README.md)

[⬆️ Volver al inicio del documento](#configuraciones-del-entorno-virtual)
