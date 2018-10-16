#!/bin/bash

setenforce 0
echo "SELinux en modo permisivo"

sysctl -w vm.max_map_count=262144
echo "Memoria virtual modificada"

#Creación y configuración de directorios para elasticsearch
mkdir -p /var/containers/elk/elasticsearch/
echo "IyA9PT09PT09PT09PT09PT09PT09IEVTTEFTVElDU0VBUkNIOiBlbGFzdGljc2VhcmNoLnltbCA9PT09PT09PT09PT09PT09PT09PT09ICMKY2x1c3Rlci5uYW1lOiAiZG9ja2VyLWNsdXN0ZXIiCm5ldHdvcmsuaG9zdDogMC4wLjAuMAojIG1pbmltdW1fbWFzdGVyX25vZGVzIG5lZWQgdG8gYmUgZXhwbGljaXRseSBzZXQgd2hlbiBib3VuZCBvbiBhIHB1YmxpYyBJUAojIHNldCB0byAxIHRvIGFsbG93IHNpbmdsZSBub2RlIGNsdXN0ZXJzCiMgRGV0YWlsczogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9wdWxsLzE3Mjg4CmRpc2NvdmVyeS56ZW4ubWluaW11bV9tYXN0ZXJfbm9kZXM6IDE=" | base64 -w0 -d > /var/containers/elk/elasticsearch/elasticsearch.yml
docker run --name=elasticsearch_wazuh_1 -p 9200:9200 -p 9300:9300 -d -e "discovery.type=single-node" -v /var/containers/elk/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:z docker.elastic.co/elasticsearch/elasticsearch-oss:6.2.2
echo "Elasticsearch creado"

#Creación y configuración de directorios para logstash
mkdir -p /var/containers/logstash/pipeline/
echo "IyA9PT09PT09PT09PT09PT09PT09IExvZ3N0YXNoOiBwaXBlbGluZS55bWwgPT09PT09PT09PT09PT09PT09PT09PSAjCmlucHV0eyAgCiAgICBiZWF0c3sKICAgICAgICBwb3J0ID0+ICI1MDQ0IiAgfQp9Cm91dHB1dHsgIAogICAgZWxhc3RpY3NlYXJjaCB7CiAgICAgICAgaG9zdHMgPT4gWydodHRwOi8vZWxhc3RpY3NlYXJjaDo5MjAwJ10gI0lQIHkgcHVlcnRvIGRlbCBjb250ZW5lZG9yIGRlIEVsYXN0aWNzZWFyY2gKICAgICAgICBpbmRleCA9PiAibG9nc3Rhc2gtJXsrWVlZWS5NTS5kZH0iICNOb21icmUgZGVsIGluZGljZSAgCiAgICAgICAgfQp9" | base64 -w0 -d > /var/containers/logstash/pipeline/pipeline.conf
#Creación de contenedor de logstash
docker run --rm -d --name=logstash_wazuh_1 --link=elasticsearch_wazuh_1:elasticsearch -v /var/containers/logstash/pipeline/:/usr/share/logstash/pipeline:z docker.elastic.co/logstash/logstash-oss:6.2.1
echo "Logstash creado"

#Creación y configuración de directorios para kibana
mkdir -p /var/containers/elk/kibana/
echo "IyA9PT09PT09PT09PT09PT09PT09IGtpYmFuYToga2liYW5hLnltbCA9PT09PT09PT09PT09PT09PT09PT09ICMKI2tpYmFuYSBjb25maWd1cmF0aW9uIGZyb20ga2liYW5hLWRvY2tlci4Kc2VydmVyLm5hbWU6IGtpYmFuYQpzZXJ2ZXIuaG9zdDogIjAiCmVsYXN0aWNzZWFyY2gudXJsOiBodHRwOi8vZWxhc3RpY3NlYXJjaDo5MjAwICNEaXJlY2NpT24gSVAgZGVsIGNvbnRlbmVkb3IgZGUgZWxhc3RpY3NlYXJjaA==" | base64 -w0 -d > /var/containers/elk/kibana/kibana.yml
docker run --name=kibana_wazuh_1 --link=elasticsearch_wazuh_1:elasticsearch -p 5601:5601 -d -v /var/containers/elk/kibana/kibana.yml:/usr/share/kibana/config/kibana.yml:z docker.elastic.co/kibana/kibana-oss:6.2.2
echo "Kibana creado"

#Creación y configuración de directorios para filebeat
mkdir -p /var/containers/logstash/filebeat/
mkdir -p /var/containers/logstash/filebeat/prospectors.d
echo "IyA9PT09PT09PT09PT09PT09PT09IEZpbGViZWF0OiBmaWxlYmVhdC55bWwgPT09PT09PT09PT09PT09PT09PT09PSAjCmZpbGViZWF0LmNvbmZpZzogIAogIHByb3NwZWN0b3JzOgogICAgcGF0aDogJHtwYXRoLmNvbmZpZ30vcHJvc3BlY3RvcnMuZC8qLnltbCAgICAgIAogICAgcmVsb2FkLmVuYWJsZWQ6IGZhbHNlICAKICBtb2R1bGVzOgogICAgcGF0aDogJHtwYXRoLmNvbmZpZ30vbW9kdWxlcy5kLyoueW1sCiAgICByZWxvYWQuZW5hYmxlZDogZmFsc2UKICAKcHJvY2Vzc29yczoKLSBhZGRfY2xvdWRfbWV0YWRhdGE6CgpvdXRwdXQubG9nc3Rhc2g6ICAKICBob3N0czogWydsb2dzdGFzaDo1MDQ0J10gI2lwIG8gbm9tYnJlIGRlIGRvbWluaW8gZGUgbG9nc3Rhc2gK" | base64 -w0 -d > /var/containers/logstash/filebeat/filebeat.yml
echo "IyA9PT09PT09PT09PT09PT09PT09IEZpbGViZWF0OiBwcnVlYmEueW1sID09PT09PT09PT09PT09PT09PT09PT0gIwotIHR5cGU6IGxvZyAgCiAgcGF0aHM6ICAgCiAgLSAvdmFyL2xvZy9kYXRhLmxvZw==" | base64 -w0 -d > /var/containers/logstash/filebeat/prospectors.d/prueba.yml
#Creación de contenedor de filebeat
docker run -d --name=filebeat_wazuh_1 --link=logstash_wazuh_1:logstash -v /var/containers/logstash/filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml -v /var/containers/logstash/filebeat/prospectors.d:/usr/share/filebeat/prospectors.d -v /var/containers/logstash/filebeat/data.log:/var/log/data.log:z docker.elastic.co/beats/filebeat:6.2.1
echo "Filebeat creado"

echo "Consulta http://localhost:5601"
