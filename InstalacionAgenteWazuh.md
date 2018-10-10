# Instalación Agente Wazuh
## Prerquisitos
* Tener permisos de superusuario

## Instalación

En cada uno de los servidores a monitorear (logueados como usuario **root**) creamos el repositorio correspondiente al agente de Wazuh, a través del siguiente comando:

```bash
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
```
Una vez creado el repositorio lo instalamos con el siguiente comando:

```bash
yum install wazuh-agent -y
```
