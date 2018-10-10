#!/bin/bash

# Creacion de Directorios para logstash
mkdir -p /var/containers/logstash/pipeline/ 

# Creacion de Directorios para filebeat
mkdir -p /var/containers/logstash/filebeat/
mkdir -p /var/containers/logstash/filebeat/prospectors.d

# Copiar archivos
cp pipeline.conf /var/containers/logstash/pipeline
cp filebeat.yml /var/containers/logstash/filebeat/
cp prueba.yml /var/containers/logstash/filebeat/prospectors.d
