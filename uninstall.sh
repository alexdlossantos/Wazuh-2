#!/bin/bash
docker rm -f elasticsearch_wazuh
docker rm -f logstash_wazuh
docker rm -f wazuh
docker rm -f kibana_wazuh
rm -rf /var/containers/wazuh

echo "El servidor de Wazuh se ha desinstalado"