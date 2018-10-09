# Wazuh
## Introducción
![Wazuh](https://www.osm-s.com/wp-content/uploads/2018/07/banner_05-1024x460.png)
Wazuh, también conocido como OSSEC Wazuh, es una completa herramienta derivada directamente de los repositorios OSSEC de manera que se pueda brindar un soporte completo a la red, cumplir con las normativas de seguridad y dotar a la herramienta de varias funciones de administración adicionales. Esta plataforma cumple sin problemas con las funciones de monitor y control de sistemas e implementa además módulos HIDS (para detectar intrusos en las redes) mejorados y funciones de seguimiento y control de estado de servidores para ofrecer a los usuarios una completa solución de monitor y seguridad totalmente de código abierto y, sobre todo, con soporte especializado.

Wazuh aporta una serie de características y módulos adicionales de código abierto al proyecto OSSEC como:

* **OSSEC Wazuh Ruleset** – Incluye el kit de reglas necesarias para que la herramienta sea capaz de cumplir con las normas PCI DSS v3.1 y CIS, así como con otras reglas adicionales para detectar posibles amenazas y poder descifrar el tráfico para un análisis a bajo nivel. Estas reglas se actualizan periódicamente.

* **OSSEC Wazuh fork** – Ofrece capacidades de registro JSON extendidas para una integración más fácil con herramientas de gestión de registros (logs) de terceros. También se incluyen modificaciones de los binarios OSSEC para implementar la RESTful API.

* **OSSEC Wazuh RESTful API** – Se utiliza para monitorizar y controlar toda una instalación OSSEC, Esta API proporciona una interfaz para controlar el administrador desde cualquier máquina capaz de enviar una petición HTTP.

* Cuenta con una serie de paquetes precompilados para facilitar su instalación en sistemas como RedHat, CentOS, Fedora, Debian, Ubuntu y Windows.
Scripts Puppet para automatizar todo el proceso de implementación y configuración de la infraestructura.

* Ofrece contenedores Docker para virtualizar fácilmente toda la plataforma.

## Componentes de Wazuh
Wazuh trabaja en una arquitectura del tipo Cliente-Servidor en la que la monitorización es centralizada en un solo servidor. En este sentido Wazuh implementa dos tipos de componentes para llevar a cabo dicha monitorización, los **Agentes** y el **Servidor**.

### Wazuh agent
Los agentes de Wazuh corren en los diferentes sistemas operativos (Windows, Linux, Solaris, BSD y Mac), con el fin de recopilar los diferentes datos del sistema operativo y enviar al servidor dicha información a traves de un canal cifrado y autenticado.

Cada agente despliega diferentes tareas para llevar a cabo la monitorización del servidor. Las tareas ejecutadas por cada agente son las siguientes:

* **Rootcheck**: Tarea dedicada a la detección de rootkits, malware y anomalias del sistema.

* **Log Collector**: Tarea dedicada a la lectura de logs que el sistema operativo produce. Dicha tarea también puede ser configurada para ejecutar ciertos comandos periódicamente y capturar la salida de dichos comandos.

* **Syscheck**: Tarea dedicada al monitoreo de integridad de archivos, detectando cambio en el contenido de un archivo, propiedad, atributos, asi como la eliminación y creación de un archivo.

* **OpenSCAP**: Tarea dedicada al escaneo periódico del sistema con el fin de encontrar aplicaciones o configuraciones vulnerables que no sigan los estándares conocidos

* **Agent Daemon**: Tarea dedicada en comprimir, encriptar y enviar los datos al servidor a tráves de un canal autenticado. Dicho proceso es ejecutado en un entorno aislado, teniendo acceso limitado al sistema monitoreado.

## Wazuh server
El componente del servidor se encarga de analizar los datos recibidos de los agentes y de activar alertas cuando un evento coincide con una regla (por ejemplo, intrusión detectada, archivo cambiado, configuración no compatible con la política, posible rootkit, etc.).

Entre las tareas ejecutadas por el agente del servidor, encontramos las siguientes:

* **Servicio de registro**: Tarea dedicada para resgitrar nuevos agentes mediante  el suministro y la distribución de claves de autenticación previamente compartidas que son exclusivas de cada agente.
La autenticación puede ser a través de TLS/SSL/contraseña fija.

* **Servicio de daemos remoto**: Tarea dedicada a recibir datos de los agentes. Hace uso de las claves previamente compartidas para validar la identidad de cada agente y para cifrar las comunicaciones entre el agente y el administrador.

* **Demonio de análisis**: Este es el proceso que realiza el análisis de datos. Utiliza decodificadores para identificar el tipo de información que se procesa (por ejemplo, eventos de Windows, registros de SSHD, registros del servidor web, etc.) y luego extrae elementos de datos relevantes de los mensajes de registro (por ejemplo, ip de origen, id de evento, usuario, etc.). Luego, mediante el uso de reglas, puede identificar patrones específicos en los registros de registro decodificados que podrían activar alertas y posiblemente incluso solicitar contramedidas automáticas (respuestas activas) como una prohibición de IP en el firewall.

* **API REST**: Proporciona una interfaz para administrar y monitorear la configuración y el estado de implementación de los agentes.


### Elastic Stack 
Wazuh se integra con Elastic Stack para proporcionar una fuente de mensajes de registro ya decodificados para ser indexados por Elasticsearch, así como una consola web en tiempo real para el análisis de alertas y registros de datos.

## Que es un Elastic Search?
Es un motor de análisis y búsqueda de texto completo altamente escalable. Elasticsearch se distribuye, lo que significa que los datos (índices) se dividen en fragmentos y cada fragmento puede tener cero o más réplicas.

Un índice de Elasticsearch es una colección de documentos que tienen características similares (como ciertos campos comunes y requisitos de retención de datos compartidos). Wazuh utiliza hasta tres índices diferentes, creados diariamente, para almacenar diferentes tipos de eventos:

* **wazuh-alerts:** índice de alertas generadas por el servidor Wazuh cada vez que un evento dispara una regla.
* **wazuh-events:** índice de todos los eventos (datos de archivo) recibidos de los agentes, ya sea que disparen o no una regla.
* **wazuh-Monitoring:** índice de datos relacionados con el estado del agente a lo largo del tiempo. La interfaz web lo utiliza para representar cuándo los agentes individuales están o han estado "Activos", "Desconectados" o "Nunca conectados".

### Arquitectura
La arquitectura Wazuh se basa en agentes que se ejecutan en hosts monitoreados que envían datos de registro a un servidor central
El servidor central decodifica y analiza la información entrante y pasa los resultados a un clúster de Elasticsearch para su indexación y almacenamiento.
## Alta disponibilidad
Las implementaciones pequeñas de Wazuh (<50 agentes), pueden ser manejadas fácilmente por un clúster de un solo nodo. Se recomiendan los clústeres de múltiples nodos cuando hay una gran cantidad de sistemas monitoreados, cuando se anticipa un gran volumen de datos y / o cuando se requiere alta disponibilidad.
![Wazuh](https://documentation.wazuh.com/current/_images/installing_wazuh1.png)

## Baja disponibilidad
En implementaciones de Wazuh más pequeñas, Wazuh y Elastic Stack con una instancia de Elasticsearch de un solo nodo pueden implementarse en un solo servidor. En este escenario, Logstash puede leer las alertas de Wazuh y / o los eventos archivados directamente desde el sistema de archivos local y enviarlos a la instancia de Elasticsearch local.
![Wazuh](https://documentation.wazuh.com/current/_images/installing_wazuh_singlehost1.png)

## Agente-Servidor
Los agentes de Wazuh utilizan el protocolo de mensajes OSSEC para enviar eventos recopilados al servidor de Wazuh a través del puerto 1514 (UDP o TCP). El servidor Wazuh luego decodifica y revisa las reglas de los eventos recibidos con el motor de análisis. Los eventos que disparan una regla se aumentan con datos de alerta, como el ID de la regla y el nombre de la regla. Los eventos pueden enviarse a uno o ambos de los siguientes archivos, dependiendo de si se ha disparado o no una regla:

* El archivo **/var/ossec/logs/archives/archives.json** contiene todos los eventos, ya sea que hayan disparado una regla o no.

* El archivo **/var/ossec/logs/alerts/alerts.json** contiene solo eventos que dispararon una regla.

Wazuh utiliza un cifrado **Blowfish** de 192 bits con una implementación completa de 16 rondas, o un cifrado **AES** con 128 bits por bloque y claves de 256 bits.

## Comunicación Wazuh - Elastic
Si la implementación no es tan grande, **Logstash** puede leer los eventos / alertas directamente del sistema de archivos local (puerto 5000/TCP), sin embargo en monitoreos con muchos servidores es necesario colocar un intermediario, **Filebeat**.

Después de que **Logstash** recopila los datos correspondientes a los eventos, este los envia **Elasticsearch** (puerto 9200/TCP) donde son indexados, para ser mostrados por **Kibana** (puerto5601/TCP).

Finalmente **Wazuh** se ejecuta dentro de Kibana y consulta constantemente la **API RESTful** (puerto 55000 / TCP en el administrador de Wazuh) para mostrar la información relacionada con la configuración y el estado del servidor y los agentes, así como para reiniciar los agentes cuando lo desee.

## Almacenamiento de eventos
Tanto las alertas como los eventos sin alertas se almacenan en archivos en el servidor Wazuh además de enviarse a Elasticsearch. Estos archivos se pueden escribir en formato JSON (.json) y / o en formato de texto plano (.log - sin campos decodificados pero más compactos). Estos archivos se comprimen y firman diariamente utilizando sumas de comprobación MD5 y SHA1. 

El directo donde se hace el almacenamiento de los archivos (en el Wazuh server) es **/var/ossec/logs/archives/**
