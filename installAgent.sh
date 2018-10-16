#!/bin/bash
#Script para la instalacion de los agentes de Wazuh
#Para CentOS 6/RHEL 6, CentOS 7/RHEL 7, Fedora 22 or greater and Amazon Linux
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF

yum install wazuh-agent -y