# Instalación del servidor Wazuh
## Prerequisitos
* Tener instalado:
    * **Docker**
    * **Docker Compose**

* Aumentar la cantidad de memoria virtual del host, de no hacer esto **Elasticsearch** probablemente NO funcionará.
    ```bash
    sysctl -w vm.max_map_count=262144
    ```

    Si la modificación desea hacerse permanentemente, es necesario agregar la misma linea, en el archivo **/etc/sysctl.conf** seguido de un reinicio del host.

    Para verificar el cambio ejecutamos:

    ```bash
    sysctl vm.max_map_count
    ```

* Contextualizar los archivos instalados o bien colocar a SELinux en modo _Permisivo_:
    * Contextualización de los archivos:

    ```bash
    chcon -R system_u: object_r: admin_home_t: s0 docker-elk /
    ```

    * Colocar a SELinux en modo permisivo:

    ```bash
    setenforce 0
    getenforce
    ```

## Instalación
Haciendo uso de Docker Compose, descargaremos el archivo de configuración a traves del siguiente comando:

```bash
curl -so docker-compose.yml https://raw.githubusercontent.com/wazuh/wazuh-docker/master/docker-compose.yml
```
**NOTA**: El archivo obligatoriamente debe tener el nombre de **docker-compose.yml**.

Enseguida modificaremos el archivo, quitando los comentarios a las etiquetas **volumes**, colocando a su vez el path de cada volumen, de forma que el archivo quedaría de la siguiente manera:

```yml
# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
version: '2'

services:
  wazuh:
    image: wazuh/wazuh:3.6.1_6.4.2
    hostname: wazuh-manager
    restart: always
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
#      - "1516:1516"
    networks:
        - docker_elk
    volumes:
      - /var/containers/wazuh/var/ossec/data:/var/ossec/data:Z
      - /var/containers/wazuh/etc/postfix:/etc/postfix:Z
      - /var/containers/wazuh/etc/filebeat:/etc/filebeat
      - /var/containers/wazuh/wazuh-config-mount/etc/ossec.conf:/wazuh-config-mount/etc/ossec.conf
    depends_on:
      - logstash
  logstash:
    image: wazuh/wazuh-logstash:3.6.1_6.4.2
    hostname: logstash
    restart: always
    volumes:
      - /var/containers/wazuh/etc/logstash/conf.d:/etc/logstash/conf.d:Z
    links:
      - elasticsearch:elasticsearch
    ports:
      - "5000:5000"
    networks:
      - docker_elk
    depends_on:
      - elasticsearch
    environment:
      - LS_HEAP_SIZE=2048m
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:6.4.2
    hostname: elasticsearch
    restart: always
    ports:
      - "9200:9200"
#      - "9300:9300"
    environment:
      - node.name=node-1
      - cluster.name=wazuh
      - network.host=0.0.0.0
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    mem_limit: 2g
    volumes:
      - /var/containers/wazuh/usr/share/elasticsearch/data:/usr/share/elasticsearch/data:Z
    networks:
        - docker_elk
  kibana:
    image: wazuh/wazuh-kibana:3.6.1_6.4.2
    hostname: kibana
    restart: always
#    ports:
#      - "5601:5601"
#    environment:
#      - ELASTICSEARCH_URL=http://elasticsearch:9200
    networks:
      - docker_elk
    depends_on:
      - elasticsearch
    links:
      - elasticsearch:elasticsearch
      - wazuh:wazuh
  nginx:
    image: wazuh/wazuh-nginx:3.6.1_6.4.2
    hostname: nginx
    restart: always
    environment:
      - NGINX_PORT=443
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/containers/wazuh/etc/nginx/conf.d:/etc/nginx/conf.d:Z
    networks:
      - docker_elk
    depends_on:
      - kibana
    links:
      - kibana:kibana

networks:
  docker_elk:
    driver: bridge
    ipam:
      config:
      - subnet: 172.25.0.0/24
```

Situados en el directorio donde esta ubicado nuestro archivo **docker-compose.yml** ejecutamos el comando:

```bash
docker-compose up
```

Si al comando anterior agregamos la bandera **-d** la ejecución se realizará en segundo plano.