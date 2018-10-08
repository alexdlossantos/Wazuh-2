# Docker Compose
## ¿Qué es Docker Compose?
Docker Compose es una herramienta que permite simplificar el uso de Docker, generando scripts que facilitan el diseño y la construcción de servicios.

## Instalación de Docker Compose
Para instalar Docker Compose basta con ejecutar los siguientes comandos:
*Descarga del paquete de **Docker Compose***

```bash
sudo curl -L "https://github.com/docker/compose/releases/download/1.22.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
```
*Se le asignan permisos de ejecución*
```bash
sudo chmod +x /usr/local/bin/docker-compose
```
*Verificamos su correcta instalación checando la versión de **Docker Compose** instalada*
```bash
docker-compose --version
```

## Desinstalación de Docker Compose
La desinstalación es a traves de:
```bash
sudo rm /usr/local/bin/docker-compose
```