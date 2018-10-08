# Wazuh
## Introducción
![Wazuh](https://www.osm-s.com/wp-content/uploads/2018/07/banner_05-1024x460.png)
Wazuh, también conocido como OSSEC Wazuh, es una completa herramienta derivada directamente de los repositorios OSSEC de manera que se pueda brindar un soporte completo a la red, cumplir con las normativas de seguridad y dotar a la herramienta de varias funciones de administración adicionales. Esta plataforma cumple sin problemas con las funciones de monitor y control de sistemas e implementa además módulos HIDS (para detectar intrusos en las redes) mejorados y funciones de seguimiento y control de estado de servidores para ofrecer a los usuarios una completa solución de monitor y seguridad totalmente de código abierto y, sobre todo, con soporte especializado.

Wazuh aporta una serie de características y módulos adicionales de código abierto al proyecto OSSEC como:

* OSSEC Wazuh Ruleset – Incluye el kit de reglas necesarias para que la herramienta sea capaz de cumplir con las normas PCI DSS v3.1 y CIS, así como con otras reglas adicionales para detectar posibles amenazas y poder descifrar el tráfico para un análisis a bajo nivel. Estas reglas se actualizan periódicamente.
* OSSEC Wazuh fork – Ofrece capacidades de registro JSON extendidas para una integración más fácil con herramientas de gestión de registros (logs) de terceros. También se incluyen modificaciones de los binarios OSSEC para implementar la RESTful API.
* OSSEC Wazuh RESTful API – Se utiliza para monitorizar y controlar toda una instalación OSSEC, Esta API proporciona una interfaz para controlar el administrador desde cualquier máquina capaz de enviar una petición HTTP.
Cuenta con una serie de paquetes precompilados para facilitar su instalación en sistemas como RedHat, CentOS, Fedora, Debian, Ubuntu y Windows.
Scripts Puppet para automatizar todo el proceso de implementación y configuración de la infraestructura.
Ofrece contenedores Docker para virtualizar fácilmente toda la plataforma.