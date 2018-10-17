# Instalación del servidor Wazuh
## Prerequisitos
* Tener instalado:
    * **Docker**

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
La instalación de **Wazuh** de manera contenerizada puede hacerse ejecutando con privilegios de superusuario el script:

```bash
./install.sh
```
A continuación se describe el proceso detallado para instalar **Wazuh**

La instalación de Wazuh queda resumida en cuatro facetas:
* **Instalación de Elasticsearch**
* **Instalación de Logstash**
* **Instalación de la API de Wazuh**
* **Instalación de Kibana**

### Instalación de Elasticsearch
El primer paso es acondicionar el servidor creando los volumenes utilizados por Elasticsearch a traves de la ejecución del comando:

```bash
mkdir -p /var/containers/wazuh/elk/elasticsearch/
```
Una vez creado el directorio, es necesario generar el archivo de configuración para Elasticsearch, **/var/containers/wazuh/elk/elasticsearch/elasticsearch.yml**.

El contenido de dicho archivo es el siguiente:

```yml
# =================== ESLASTICSEARCH: elasticsearch.yml ====================== #
cluster.name: "docker-cluster"
network.host: 0.0.0.0
# minimum_master_nodes need to be explicitly set when bound on a public IP
# set to 1 to allow single node clusters
# Details: https://github.com/elastic/elasticsearch/pull/17288
discovery.zen.minimum_master_nodes: 1
```

Finalmente procedemos a crear el contenedor correspondiente a Elasticsearch con el comando:

```bash
docker run --name=elasticsearch_wazuh -p 9200:9200 -p 9300:9300 -d -e "discovery.type=single-node" -v /var/containers/wazuh/elk/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:z -v /etc/localtime:/etc/localtime:ro docker.elastic.co/elasticsearch/elasticsearch:6.4.2
```

### Instalación de Logstash
El primer paso es acondicionar el servidor creando los volumenes utilizados por Logstash a traves de la ejecución del comando:

```bash
mkdir -p /var/containers/wazuh/logstash/pipeline/
```
Una vez creado el directorio, es necesario generar el archivo de configuración para Logstash, **/var/containers/wazuh/logstash/pipeline/pipeline.yml**.

El contenido de dicho archivo es el siguiente:

```yml
# =================== Logstash: pipeline.yml ====================== #
input{  
    beats{
        port => "5000"  }
}
output{  
    elasticsearch {
        hosts => ['http://elasticsearch:9200'] #IP y puerto del contenedor de Elasticsearch
        index => "logstash-%{+YYYY.MM.dd}" #Nombre del indice  
        }
}
```
Finalmente procedemos a crear el contenedor correspondiente a Logstash con el comando:

```bash
docker run --rm -d --name=logstash_wazuh --link=elasticsearch_wazuh:elasticsearch -v /var/containers/wazuh/logstash/pipeline/:/usr/share/logstash/pipeline/bin:z -v /etc/localtime:/etc/localtime:ro docker.elastic.co/logstash/logstash-oss:6.2.1
```

### Instalación de Wazuh
El primer paso es acondicionar el servidor creando los volumenes utilizados por Wazuh a traves de la ejecución del comando:

```bash
mkdir -p /var/containers/wazuh/wazuh/wazuh-config-mount/etc/
mkdir -p /var/containers/wazuh/wazuh/etc/filebeat/
mkdir -p /var/containers/wazuh/wazuh/var/ossec/etc/shared/
mkdir -p /var/containers/wazuh/wazuh/var/log/
touch /var/containers/wazuh/wazuh/var/log/mail.log
```
A coninuación crearemos una serie de archivos que permiten la configuración de la API de Wazuh.

El primero de ellos es el archivo **/var/containers/wazuh/wazuh/etc/filebeat/filebeat.yml** cuyo contenido es el siguiente:

```yml
# =================== Filebeat: filebeat.yml ====================== #
filebeat.config:  
  prospectors:
    path: ${path.config}/prospectors.d/*.yml      
    reload.enabled: false  
  modules:
    path: ${path.config}/modules.d/*.yml
    reload.enabled: false
  
processors:
- add_cloud_metadata:

output.logstash:  
  hosts: ['logstash:5000'] #ip o nombre de dominio de logstash
```

El siguiente archivo es **/var/containers/wazuh/wazuh/wazuh-config-mount/etc/ossec.conf**

**NOTA**: Este archivo contiene las especificaciones de la forma en la que monitoreará Wazuh.

A continuación se muestra su contenido:

```conf
<!--
  Wazuh - Manager - Default configuration.
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->

<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
  </global>

  <!-- Choose between plain or json format (or both) for internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>udp</protocol>
  </remote>

  <!-- Policy monitoring for PCI requeriments-->
  <rootcheck>
    <disabled>no</disabled>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <content type="xccdf" path="ssg-debian-8-ds.xml"> <!-- Se especifica el tipo de srevidores -->
      <profile>xccdf_org.ssgproject.content_profile_common</profile>
      <profile>xccdf_org.ssgproject.content_profile_standard</profile>
      <profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
    </content>
    <content type="oval" path="cve-debian-oval.xml"/>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
  </wodle>

  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>1d</interval>
    <run_on_start>yes</run_on_start>
    <update_ubuntu_oval interval="60m" version="16,14,12">yes</update_ubuntu_oval>
    <update_redhat_oval interval="60m" version="7,6,5">yes</update_redhat_oval>
  </wodle>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 3 times -->
    <auto_ignore>no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>
    <!-- Con esta linea se especifica a que archivo hay que monitorear con mas detalle
    <directories check_all="yes" report_changes="yes">/root/credit_cards</directories> -->
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!--
  <active-response>
    active-response options here
  </active-response>
  -->

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tan |grep LISTEN |grep -v 127.0.0.1 | sort</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 5</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <location>/var/log/*.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <!-- Configuration for ossec-authd
       To enable this service, run:
       ossec-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>yes</use_source_ip>
    <force_insert>yes</force_insert>
    <force_time>0</force_time>
    <purge>yes</purge>
    <use_password>no</use_password>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

</ossec_config>
```
Los isguientes archivos forman parte de las reglas para el monitoreo de aspectos como rookits, trojans etc.

Archivo **/var/containers/wazuh/wazuh/var/ossec/etc/shared/rootkit_files.txt**

```txt
# rootkit_files.txt, (C) Daniel B. Cid
# Imported from the rootcheck project.
#
# Blank lines and lines starting with '#' are ignored.
#
# Each line must be in the following format:
# file_name ! Name ::Link to it
#
# Files that start with an '*' will be searched in the whole system.

# Bash door
tmp/mcliZokhb           ! Bash door ::/rootkits/bashdoor.php
tmp/mclzaKmfa           ! Bash door ::/rootkits/bashdoor.php

# adore Worm
dev/.shit/red.tgz       ! Adore Worm ::/rootkits/adorew.php
usr/lib/libt            ! Adore Worm ::/rootkits/adorew.php
usr/bin/adore           ! Adore Worm ::/rootkits/adorew.php
*/klogd.o               ! Adore Worm ::/rootkits/adorew.php
*/red.tar               ! Adore Worm ::/rootkits/adorew.php

# T.R.K rootkit
usr/bin/soucemask       ! TRK rootkit ::/rootkits/trk.php
usr/bin/sourcemask      ! TRK rootkit ::/rootkits/trk.php

# 55.808.A Worm
tmp/.../a               ! 55808.A Worm ::
tmp/.../r               ! 55808.A Worm ::

# Volc Rootkit
usr/lib/volc            ! Volc Rootkit ::
usr/bin/volc            ! Volc Rootkit ::

# Illogic
lib/security/.config    ! Illogic Rootkit ::rootkits/illogic.php
usr/bin/sia             ! Illogic Rootkit ::rootkits/illogic.php
etc/ld.so.hash          ! Illogic Rootkit ::rootkits/illogic.php
*/uconf.inv             ! Illogic Rootkit ::rootkits/illogic.php

# T0rnkit
usr/src/.puta           ! t0rn Rootkit ::rootkits/torn.php
usr/info/.t0rn          ! t0rn Rootkit ::rootkits/torn.php
lib/ldlib.tk            ! t0rn Rootkit ::rootkits/torn.php
etc/ttyhash             ! t0rn Rootkit ::rootkits/torn.php
sbin/xlogin             ! t0rn Rootkit ::rootkits/torn.php
*/ldlib.tk              ! t0rn Rootkit ::rootkits/torn.php
*/.t0rn                 ! t0rn Rootkit ::rootkits/torn.php
*/.puta                 ! t0rn Rootkit ::rootkits/torn.php

# RK17
bin/rtty                        ! RK17 ::
bin/squit                       ! RK17 ::
sbin/pback                      ! RK17 ::
proc/kset                       ! RK17 ::
usr/src/linux/modules/autod.o   ! RK17 ::
usr/src/linux/modules/soundx.o  ! RK17 ::

# Ramen Worm
usr/lib/ldlibps.so      ! Ramen Worm ::rootkits/ramen.php
usr/lib/ldlibns.so      ! Ramen Worm ::rootkits/ramen.php
usr/lib/ldliblogin.so   ! Ramen Worm ::rootkits/ramen.php
usr/src/.poop           ! Ramen Worm ::rootkits/ramen.php
tmp/ramen.tgz           ! Ramen Worm ::rootkits/ramen.php
etc/xinetd.d/asp        ! Ramen Worm ::rootkits/ramen.php

# Sadmind/IIS Worm
dev/cuc                 ! Sadmind/IIS Worm ::

# Monkit
lib/defs                ! Monkit ::
usr/lib/libpikapp.a     ! Monkit found ::

# RSHA
usr/bin/kr4p            ! RSHA ::
usr/bin/n3tstat         ! RSHA ::
usr/bin/chsh2           ! RSHA ::
usr/bin/slice2          ! RSHA ::
etc/rc.d/rsha           ! RSHA ::

# ShitC worm
bin/home                ! ShitC ::
sbin/home               ! ShitC ::
usr/sbin/in.slogind     ! ShitC ::

# Omega Worm
dev/chr                 ! Omega Worm ::

# rh-sharpe
bin/.ps                 ! Rh-Sharpe ::
usr/bin/cleaner         ! Rh-Sharpe ::
usr/bin/slice           ! Rh-Sharpe ::
usr/bin/vadim           ! Rh-Sharpe ::
usr/bin/.ps             ! Rh-Sharpe ::
bin/.lpstree            ! Rh-Sharpe ::
usr/bin/.lpstree        ! Rh-Sharpe ::
usr/bin/lnetstat        ! Rh-Sharpe ::
bin/lnetstat            ! Rh-Sharpe ::
usr/bin/ldu             ! Rh-Sharpe ::
bin/ldu                 ! Rh-Sharpe ::
usr/bin/lkillall        ! Rh-Sharpe ::
bin/lkillall            ! Rh-Sharpe ::
usr/include/rpcsvc/du   ! Rh-Sharpe ::

# Maniac RK
usr/bin/mailrc          ! Maniac RK ::

# Showtee / Romanian
usr/lib/.egcs           ! Showtee ::
usr/lib/.wormie         ! Showtee ::
usr/lib/.kinetic        ! Showtee ::
usr/lib/liblog.o        ! Showtee ::
usr/include/addr.h      ! Showtee / Romanian rootkit ::
usr/include/cron.h      ! Showtee ::
usr/include/file.h      ! Showtee / Romanian rootkit ::
usr/include/syslogs.h   ! Showtee / Romanian rootkit ::
usr/include/proc.h      ! Showtee / Romanian rootkit ::
usr/include/chk.h       ! Showtee ::
usr/sbin/initdl         ! Romanian rootkit ::
usr/sbin/xntps          ! Romanian rootkit ::

# Optickit
usr/bin/xchk            ! Optickit ::
usr/bin/xsf             ! Optickit ::

# LDP worm
dev/.kork           ! LDP Worm ::
bin/.login          ! LDP Worm ::
bin/.ps             ! LDP Worm ::

# Telekit
dev/hda06           ! TeLeKit trojan ::
usr/info/libc1.so   ! TeleKit trojan ::

# Tribe bot
dev/wd4     ! Tribe bot ::

# LRK
dev/ida/.inet       ! LRK rootkit ::rootkits/lrk.php
*/bindshell         ! LRK rootkit ::rootkits/lrk.php

# Adore Rootkit
etc/bin/ava         ! Adore Rootkit ::
etc/sbin/ava        ! Adore Rootkit ::

# Slapper
tmp/.bugtraq            ! Slapper installed ::
tmp/.bugtraq.c          ! Slapper installed ::
tmp/.cinik              ! Slapper installed ::
tmp/.b                  ! Slapper installed ::
tmp/httpd               ! Slapper installed ::
tmp./update             ! Slapper installed ::
tmp/.unlock             ! Slapper installed ::
tmp/.font-unix/.cinik   ! Slapper installed ::
tmp/.cinik              ! Slapper installed ::

# Scalper
tmp/.uua            ! Scalper installed ::
tmp/.a              ! Scalper installed ::

# Knark
proc/knark          ! Knark Installed ::rootkits/knark.php
dev/.pizda          ! Knark Installed ::rootkits/knark.php
dev/.pula           ! Knark Installed ::rootkits/knark.php
dev/.pula           ! Knark Installed ::rootkits/knark.php
*/taskhack          ! Knark Installed ::rootkits/knark.php
*/rootme            ! Knark Installed ::rootkits/knark.php
*/nethide           ! Knark Installed ::rootkits/knark.php
*/hidef             ! Knark Installed ::rootkits/knark.php
*/ered              ! Knark Installed ::rootkits/knark.php

# Lion worm
dev/.lib            ! Lion Worm ::rootkits/lion.php
dev/.lib/1iOn.sh    ! Lion Worm ::rootkits/lion.php
bin/mjy             ! Lion Worm ::rootkits/lion.php
bin/in.telnetd      ! Lion Worm ::rootkits/lion.php
usr/info/torn       ! Lion Worm ::rootkits/lion.php
*/1iOn\.sh          ! Lion Worm ::rootkits/lion.php

# Bobkit
usr/include/.../        ! Bobkit Rootkit ::rootkits/bobkit.php
usr/lib/.../            ! Bobkit Rootkit ::rootkits/bobkit.php
usr/sbin/.../           ! Bobkit Rootkit ::rootkits/bobkit.php
usr/bin/ntpsx           ! Bobkit Rootkit ::rootkits/bobkit.php
tmp/.bkp                ! Bobkit Rootkit ::rootkits/bobkit.php
usr/lib/.bkit-          ! Bobkit Rootkit ::rootkits/bobkit.php
*/bkit-                 ! Bobkit Rootkit ::rootkits/bobkit.php

# Hidrootkit
var/lib/games/.k        ! Hidr00tkit ::

# Ark
dev/ptyxx       ! Ark rootkit ::

# Mithra Rootkit
usr/lib/locale/uboot        ! Mithra`s rootkit ::

# Optickit
usr/bin/xsf         ! OpticKit ::
usr/bin/xchk        ! OpticKit ::

# LOC rookit
tmp/xp          ! LOC rookit ::
tmp/kidd0.c     ! LOC rookit ::
tmp/kidd0       ! LOC rookit ::

# TC2 worm
usr/info/.tc2k      ! TC2 Worm ::
usr/bin/util        ! TC2 Worm ::
usr/sbin/initcheck  ! TC2 Worm ::
usr/sbin/ldb        ! TC2 Worm ::

# Anonoiyng rootkit
usr/sbin/mech       ! Anonoiyng rootkit ::
usr/sbin/kswapd     ! Anonoiyng rootkit ::

# SuckIt
lib/.x              ! SuckIt rootkit ::
*/hide.log          ! Suckit rootkit ::
lib/sk              ! SuckIT rootkit ::

# Beastkit
usr/local/bin/bin       ! Beastkit rootkit ::rootkits/beastkit.php
usr/man/.man10          ! Beastkit rootkit ::rootkits/beastkit.php
usr/sbin/arobia         ! Beastkit rootkit ::rootkits/beastkit.php
usr/lib/elm/arobia      ! Beastkit rootkit ::rootkits/beastkit.php
usr/local/bin/.../bktd  ! Beastkit rootkit ::rootkits/beastkit.php

# Tuxkit
dev/tux             ! Tuxkit rootkit ::rootkits/Tuxkit.php
usr/bin/xsf         ! Tuxkit rootkit ::rootkits/Tuxkit.php
usr/bin/xchk        ! Tuxkit rootkit ::rootkits/Tuxkit.php
*/.file             ! Tuxkit rootkit ::rootkits/Tuxkit.php
*/.addr             ! Tuxkit rootkit ::rootkits/Tuxkit.php

# Old rootkits
usr/include/rpc/ ../kit     ! Old rootkits ::rootkits/Old.php
usr/include/rpc/ ../kit2    ! Old rootkits ::rootkits/Old.php
usr/doc/.sl                 ! Old rootkits ::rootkits/Old.php
usr/doc/.sp                 ! Old rootkits ::rootkits/Old.php
usr/doc/.statnet            ! Old rootkits ::rootkits/Old.php
usr/doc/.logdsys            ! Old rootkits ::rootkits/Old.php
usr/doc/.dpct               ! Old rootkits ::rootkits/Old.php
usr/doc/.gifnocfi           ! Old rootkits ::rootkits/Old.php
usr/doc/.dnif               ! Old rootkits ::rootkits/Old.php
usr/doc/.nigol              ! Old rootkits ::rootkits/Old.php

# Kenga3 rootkit
usr/include/. .         ! Kenga3 rootkit

# ESRK rootkit
usr/lib/tcl5.3          ! ESRK rootkit

# Fu rootkit
sbin/xc                 ! Fu rootkit
usr/include/ivtype.h    ! Fu rootkit
bin/.lib                ! Fu rootkit

# ShKit rootkit
lib/security/.config    ! ShKit rootkit
etc/ld.so.hash          ! ShKit rootkit

# AjaKit rootkit
lib/.ligh.gh            ! AjaKit rootkit
lib/.libgh.gh           ! AjaKit rootkit
lib/.libgh-gh           ! AjaKit rootkit
dev/tux                 ! AjaKit rootkit
dev/tux/.proc           ! AjaKit rootkit
dev/tux/.file           ! AjaKit rootkit

# zaRwT rootkit
bin/imin                ! zaRwT rootkit
bin/imout               ! zaRwT rootkit

# Madalin rootkit
usr/include/icekey.h    ! Madalin rootkit
usr/include/iceconf.h   ! Madalin rootkit
usr/include/iceseed.h   ! Madalin rootkit

# shv5 rootkit XXX http://www.askaboutskating.com/forum/.../shv5/setup
lib/libsh.so            ! shv5 rootkit
usr/lib/libsh           ! shv5 rootkit

# BMBL rootkit (http://www.giac.com/practical/GSEC/Steve_Terrell_GSEC.pdf)
etc/.bmbl               ! BMBL rootkit
etc/.bmbl/sk            ! BMBL rootkit

# rootedoor rootkit
*/rootedoor             ! Rootedoor rootkit

# 0vason rootkit
*/ovas0n                ! ovas0n rootkit ::/rootkits/ovason.php
*/ovason                ! ovas0n rootkit ::/rootkits/ovason.php

# Rpimp reverse telnet
*/rpimp                 ! rpv21 (Reverse Pimpage)::/rootkits/rpimp.php

# Cback Linux worm
tmp/cback              ! cback worm ::/rootkits/cback.php
tmp/derfiq             ! cback worm ::/rootkits/cback.php

# aPa Kit (from rkhunter)
usr/share/.aPa          ! Apa Kit

# enye-sec Rootkit
etc/.enyelkmHIDE^IT.ko  ! enye-sec Rootkit ::/rootkits/enye-sec.php

# Override Rootkit
dev/grid-hide-pid-     ! Override rootkit ::/rootkits/override.php
dev/grid-unhide-pid-   ! Override rootkit ::/rootkits/override.php
dev/grid-show-pids     ! Override rootkit ::/rootkits/override.php
dev/grid-hide-port-    ! Override rootkit ::/rootkits/override.php
dev/grid-unhide-port-  ! Override rootkit ::/rootkits/override.php

# PHALANX rootkit
usr/share/.home*        ! PHALANX rootkit ::
usr/share/.home*/tty    ! PHALANX rootkit ::
etc/host.ph1            ! PHALANX rootkit ::
bin/host.ph1            ! PHALANX rootkit ::

# ZK rootkit (http://honeyblog.org/junkyard/reports/redhat-compromise2.pdf)
# and from chkrootkit
usr/share/.zk                   ! ZK rootkit ::
usr/share/.zk/zk                ! ZK rootkit ::
etc/1ssue.net                   ! ZK rootkit ::
usr/X11R6/.zk                   ! ZK rootkit ::
usr/X11R6/.zk/xfs               ! ZK rootkit ::
usr/X11R6/.zk/echo              ! ZK rootkit ::
etc/sysconfig/console/load.zk   ! ZK rootkit ::

# Public sniffers
*/.linux-sniff          ! Sniffer log ::
*/sniff-l0g             ! Sniffer log ::
*/core_$                ! Sniffer log ::
*/tcp.log               ! Sniffer log ::
*/chipsul               ! Sniffer log ::
*/beshina               ! Sniffer log ::
*/.owned$               | Sniffer log ::

# Solaris worm -
# http://blogs.sun.com/security/entry/solaris_in_telnetd_worm_seen
var/adm/.profile        ! Solaris Worm ::
var/spool/lp/.profile   ! Solaris Worm ::
var/adm/sa/.adm         ! Solaris Worm ::
var/spool/lp/admins/.lp ! Solaris Worm ::

# Suspicious files
etc/rc.d/init.d/rc.modules  ! Suspicious file ::rootkits/Suspicious.php
lib/ldd.so                  ! Suspicious file ::rootkits/Suspicious.php
usr/man/muie                ! Suspicious file ::rootkits/Suspicious.php
usr/X11R6/include/pain      ! Suspicious file ::rootkits/Suspicious.php
usr/bin/sourcemask          ! Suspicious file ::rootkits/Suspicious.php
usr/bin/ras2xm              ! Suspicious file ::rootkits/Suspicious.php
usr/bin/ddc                 ! Suspicious file ::rootkits/Suspicious.php
usr/bin/jdc                 ! Suspicious file ::rootkits/Suspicious.php
usr/sbin/in.telnet          ! Suspicious file ::rootkits/Suspicious.php
sbin/vobiscum               ! Suspicious file ::rootkits/Suspicious.php
usr/sbin/jcd                ! Suspicious file ::rootkits/Suspicious.php
usr/sbin/atd2               ! Suspicious file ::rootkits/Suspicious.php
usr/bin/ishit               ! Suspicious file ::rootkits/Suspicious.php
usr/bin/.etc                ! Suspicious file ::rootkits/Suspicious.php
usr/bin/xstat               ! Suspicious file ::rootkits/Suspicious.php
var/run/.tmp                ! Suspicious file ::rootkits/Suspicious.php
usr/man/man1/lib/.lib       ! Suspicious file ::rootkits/Suspicious.php
usr/man/man2/.man8          ! Suspicious file ::rootkits/Suspicious.php
var/run/.pid                ! Suspicious file ::rootkits/Suspicious.php
lib/.so                     ! Suspicious file ::rootkits/Suspicious.php
lib/.fx                     ! Suspicious file ::rootkits/Suspicious.php
lib/lblip.tk                ! Suspicious file ::rootkits/Suspicious.php
usr/lib/.fx                 ! Suspicious file ::rootkits/Suspicious.php
var/local/.lpd              ! Suspicious file ::rootkits/Suspicious.php
dev/rd/cdb                  ! Suspicious file ::rootkits/Suspicious.php
dev/.rd/                    ! Suspicious file ::rootkits/Suspicious.php
usr/lib/pt07                ! Suspicious file ::rootkits/Suspicious.php
usr/bin/atm                 ! Suspicious file ::rootkits/Suspicious.php
tmp/.cheese                 ! Suspicious file ::rootkits/Suspicious.php
dev/.arctic                 ! Suspicious file ::rootkits/Suspicious.php
dev/.xman                   ! Suspicious file ::rootkits/Suspicious.php
dev/.golf                   ! Suspicious file ::rootkits/Suspicious.php
dev/srd0                    ! Suspicious file ::rootkits/Suspicious.php
dev/ptyzx                   ! Suspicious file ::rootkits/Suspicious.php
dev/ptyzg                   ! Suspicious file ::rootkits/Suspicious.php
dev/xdf1                    ! Suspicious file ::rootkits/Suspicious.php
dev/ttyop                   ! Suspicious file ::rootkits/Suspicious.php
dev/ttyof                   ! Suspicious file ::rootkits/Suspicious.php
dev/hd7                     ! Suspicious file ::rootkits/Suspicious.php
dev/hdx1                    ! Suspicious file ::rootkits/Suspicious.php
dev/hdx2                    ! Suspicious file ::rootkits/Suspicious.php
dev/xdf2                    ! Suspicious file ::rootkits/Suspicious.php
dev/ptyp                    ! Suspicious file ::rootkits/Suspicious.php
dev/ptyr                    ! Suspicious file ::rootkits/Suspicious.php
sbin/pback                  ! Suspicious file ::rootkits/Suspicious.php
usr/man/man3/psid           ! Suspicious file ::rootkits/Suspicious.php
proc/kset                   ! Suspicious file ::rootkits/Suspicious.php
usr/bin/gib                 ! Suspicious file ::rootkits/Suspicious.php
usr/bin/snick               ! Suspicious file ::rootkits/Suspicious.php
usr/bin/kfl                 ! Suspicious file ::rootkits/Suspicious.php
tmp/.dump                   ! Suspicious file ::rootkits/Suspicious.php
var/.x                      ! Suspicious file ::rootkits/Suspicious.php
var/.x/psotnic              ! Suspicious file ::rootkits/Suspicious.php
*/.log                      ! Suspicious file ::rootkits/Suspicious.php
*/ecmf                      ! Suspicious file ::rootkits/Suspicious.php
*/mirkforce                 ! Suspicious file ::rootkits/Suspicious.php
*/mfclean                   ! Suspicious file ::rootkits/Suspicious.php
```

Archivo **/var/containers/wazuh/wazuh/var/ossec/etc/shared/rootkit_trojans.txt**

```txt
# rootkit_trojans.txt, (C) Daniel B. Cid
# Imported from the rootcheck project.
# Some entries taken from the chkrootkit project.
#
# Blank lines and lines starting with '#' are ignored.
#
# Each line must be in the following format:
# file_name !string_to_search!Description

# Common binaries and public trojan entries
ls          !bash|^/bin/sh|dev/[^clu]|\.tmp/lsfile|duarawkz|/prof|/security|file\.h!
env         !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
echo        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chown       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chmod       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chgrp       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
cat         !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
bash        !proc\.h|/dev/[0-9]|/dev/[hijkz]!
sh          !proc\.h|/dev/[0-9]|/dev/[hijkz]!
uname       !bash|^/bin/sh|file\.h|proc\.h|^/bin/.*sh!
date        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cln]|^/bin/.*sh!
du          !w0rm|/prof|file\.h!
df          !bash|^/bin/sh|file\.h|proc\.h|/dev/[^clurdv]|^/bin/.*sh!
login       !elite|SucKIT|xlogin|vejeta|porcao|lets_log|sukasuk!
passwd      !bash|file\.h|proc\.h|/dev/ttyo|/dev/[A-Z]|/dev/[b-s,uvxz]!
mingetty    !bash|Dimensioni|pacchetto!
chfn        !bash|file\.h|proc\.h|/dev/ttyo|/dev/[A-Z]|/dev/[a-s,uvxz]!
chsh        !bash|file\.h|proc\.h|/dev/ttyo|/dev/[A-Z]|/dev/[a-s,uvxz]!
mail        !bash|file\.h|proc\.h|/dev/[^nu]!
su          !/dev/[d-s,abuvxz]|/dev/[A-D]|/dev/[F-Z]|/dev/[0-9]|satori|vejeta|conf\.inv!
sudo        !satori|vejeta|conf\.inv!
crond       !/dev/[^nt]|bash!
gpm         !bash|mingetty!
ifconfig    !bash|^/bin/sh|/dev/tux|session.null|/dev/[^cludisopt]!
diff        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^n]|^/bin/.*sh!
md5sum      !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
hdparm      !bash|/dev/ida!
ldd         !/dev/[^n]|proc\.h|libshow.so|libproc.a!

# Trojan entries for troubleshooting binaries
grep        !bash|givemer!
egrep       !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
find        !bash|/dev/[^tnlcs]|/prof|/home/virus|file\.h!
lsof        !/prof|/dev/[^apcmnfk]|proc\.h|bash|^/bin/sh|/dev/ttyo|/dev/ttyp!
netstat     !bash|^/bin/sh|/dev/[^aik]|/prof|grep|addr\.h!
top         !/dev/[^npi3st%]|proc\.h|/prof/!
ps          !/dev/ttyo|\.1proc|proc\.h|bash|^/bin/sh!
tcpdump     !bash|^/bin/sh|file\.h|proc\.h|/dev/[^bu]|^/bin/.*sh!
pidof       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^f]|^/bin/.*sh!
fuser       !bash|^/bin/sh|file\.h|proc\.h|/dev/[a-dtz]|^/bin/.*sh!
w           !uname -a|proc\.h|bash!

# Trojan entries for common daemons
sendmail    !bash|fuck!
named       !bash|blah|/dev/[0-9]|^/bin/sh!
inetd       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^un%]|^/bin/.*sh!
apachectl   !bash|^/bin/sh|file\.h|proc\.h|/dev/[^n]|^/bin/.*sh!
sshd        !check_global_passwd|panasonic|satori|vejeta|\.ark|/hash\.zk|bash|/dev[a-s]|/dev[A-Z]/!
syslogd     !bash|/usr/lib/pt07|/dev/[^cln]]|syslogs\.h|proc\.h!
xinetd      !bash|file\.h|proc\.h!
in.telnetd  !cterm100|vt350|VT100|ansi-term|bash|^/bin/sh|/dev[A-R]|/dev/[a-z]/!
in.fingerd  !bash|^/bin/sh|cterm100|/dev/!
identd      !bash|^/bin/sh|file\.h|proc\.h|/dev/[^n]|^/bin/.*sh!
init        !bash|/dev/h
tcpd        !bash|proc\.h|p1r0c4|hack|/dev/[^n]!
rlogin      !p1r0c4|r00t|bash|/dev/[^nt]!

# Kill trojan
killall     !/dev/[^t%]|proc\.h|bash|tmp!
kill        !/dev/[ab,d-k,m-z]|/dev/[F-Z]|/dev/[A-D]|/dev/[0-9]|proc\.h|bash|tmp!

# Rootkit entries
/etc/rc.d/rc.sysinit    !enyelkmHIDE! enye-sec Rootkit

# ZK rootkit (http://honeyblog.org/junkyard/reports/redhat-compromise2.pdf)
/etc/sysconfig/console/load.zk   !/bin/sh! ZK rootkit
/etc/sysconfig/console/load.zk   !usr/bin/run! ZK rootkit

# Modified /etc/hosts entries
# Idea taken from:
# http://blog.tenablesecurity.com/2006/12/detecting_compr.html
# http://www.sophos.com/security/analyses/trojbagledll.html
# http://www.f-secure.com/v-descs/fantibag_b.shtml
/etc/hosts  !^[^#]*avp.ch!Anti-virus site on the hosts file
/etc/hosts  !^[^#]*avp.ru!Anti-virus site on the hosts file
/etc/hosts  !^[^#]*awaps.net! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*ca.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*mcafee.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*microsoft.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*f-secure.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*sophos.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*symantec.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*my-etrust.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*nai.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*networkassociates.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*viruslist.ru! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*kaspersky! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*symantecliveupdate.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*grisoft.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*clamav.net! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*bitdefender.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*antivirus.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*sans.org! Security site on the hosts file
```
Archivo **/var/containers/wazuh/wazuh/var/ossec/etc/shared/system_audit_rcl.txt**

```txt
# OSSEC Linux Audit - (C) 2007 Daniel B. Cid - dcid@ossec.net
#
# PCI Tagging by Wazuh <ossec@wazuh.com>.
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

$php.ini=/etc/php.ini,/var/www/conf/php.ini,/etc/php5/apache2/php.ini;
$web_dirs=/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www;

# PHP checks
[PHP - Register globals are enabled] [any] []
f:$php.ini -> r:^register_globals = On;

# PHP checks
[PHP - Expose PHP is enabled] [any] []
f:$php.ini -> r:^expose_php = On;

# PHP checks
[PHP - Allow URL fopen is enabled] [any] []
f:$php.ini -> r:^allow_url_fopen = On;

# PHP checks
[PHP - Displaying of errors is enabled] [any] []
f:$php.ini -> r:^display_errors = On;

# PHP checks - consider open_basedir && disable_functions


## Looking for common web exploits (might indicate that you are owned).
## Using http://dcid.me/blog/logsamples/webattacks_links as a reference.
#[Web exploits - Possible compromise] [any] []
#d:$web_dirs -> .txt$ -> r:^<?php|^#!;

## Looking for common web exploits files (might indicate that you are owned).
## There are not specific, like the above.
## Using http://dcid.me/blog/logsamples/webattacks_links as a reference.
[Web exploits (uncommon file name inside htdocs) - Possible compromise  {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^.yop$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^id$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^.ssh$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^...$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^.shell$;

## Looking for outdated Web applications
## Taken from http://sucuri.net/latest-versions
[Web vulnerability - Outdated WordPress installation {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://sucuri.net/latest-versions]
d:$web_dirs -> ^version.php$ -> r:^\.wp_version && >:$wp_version = '4.4.2';

[Web vulnerability - Outdated Joomla installation {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://sucuri.net/latest-versions]
d:$web_dirs -> ^version.php$ -> r:var \.RELEASE && r:'3.4.8';

[Web vulnerability - Outdated osCommerce (v2.2) installation {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://sucuri.net/latest-versions]
d:$web_dirs -> ^application_top.php$ -> r:'osCommerce 2.2-;

## Looking for known backdoors
[Web vulnerability - Backdoors / Web based malware found - eval(base64_decode {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> .php$ -> r:eval\(base64_decode\(\paWYo;

[Web vulnerability - Backdoors / Web based malware found - eval(base64_decode(POST {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> .php$ -> r:eval\(base64_decode\(\S_POST;

[Web vulnerability - .htaccess file compromised {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://blog.sucuri.net/2011/05/understanding-htaccess-attacks-part-1.html]
d:$web_dirs -> ^.htaccess$ -> r:RewriteCond \S+HTTP_REFERERS \S+google;

[Web vulnerability - .htaccess file compromised - auto append {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://blog.sucuri.net/2011/05/understanding-htaccess-attacks-part-1.html]
d:$web_dirs -> ^.htaccess$ -> r:php_value auto_append_file;
```
Archivo **/var/containers/wazuh/wazuh/var/ossec/etc/shared/system_audit_ssh.txt**

```txt
#  SSH Rootcheck
#
#  Created by Wazuh, Inc. <ossec@wazuh.com>.
#  This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
#


$sshd_file=/etc/ssh/sshd_config;


# Listen PORT != 22
# The option Port specifies on which port number ssh daemon listens for incoming connections.
# Changing the default port you may reduce the number of successful attacks from zombie bots, an attacker or bot doing port-scanning can quickly identify your SSH port.
[SSH Hardening - 1: Port 22 {PCI_DSS: 2.2.4}] [any] [1]
f:$sshd_file -> !r:^# && r:Port\.+22;


# Protocol 2
# The Protocol parameter dictates which version of the SSH communication and encryption protocols are in use.
# Version 1 of the SSH protocol has weaknesses.
[SSH Hardening - 2: Protocol 1 {PCI_DSS: 2.2.4}] [any] [2]
f:$sshd_file -> !r:^# && r:Protocol\.+1;


# PermitRootLogin no
# The option PermitRootLogin specifies whether root can log in using ssh.
# If you want log in as root, you should use the option "Match" and restrict it to a few IP addresses.
[SSH Hardening - 3: Root can log in] [any] [3]
f:$sshd_file -> !r:^\s*PermitRootLogin\.+no;


# PubkeyAuthentication yes
# Access only by public key
# Generally people will use weak passwords and have poor password practices. Keys are considered stronger than password.
[SSH Hardening - 4: No Public Key authentication {PCI_DSS: 2.2.4}] [any] [4]
f:$sshd_file -> !r:^\s*PubkeyAuthentication\.+yes;


# PasswordAuthentication no
# The option PasswordAuthentication specifies whether we should use password-based authentication.
# Use public key authentication instead of passwords
[SSH Hardening - 5: Password Authentication {PCI_DSS: 2.2.4}] [any] [5]
f:$sshd_file -> !r:^\s*PasswordAuthentication\.+no;


# PermitEmptyPasswords no
# The option PermitEmptyPasswords specifies whether the server allows logging in to accounts with a null password
# Accounts with null passwords are a bad practice.
[SSH Hardening - 6: Empty passwords allowed {PCI_DSS: 2.2.4}] [any] [6]
f:$sshd_file -> !r:^\s*PermitEmptyPasswords\.+no;


# IgnoreRhosts yes
# The option IgnoreRhosts specifies whether rhosts or shosts files should not be used in authentication.
# For security reasons it is recommended to no use rhosts or shosts files for authentication.
[SSH Hardening - 7: Rhost or shost used for authentication {PCI_DSS: 2.2.4}] [any] [7]
f:$sshd_file -> !r:^\s*IgnoreRhosts\.+yes;


# LoginGraceTime 30
# The option LoginGraceTime specifies how long in seconds after a connection request the server will wait before disconnecting if the user has not successfully logged in.
# 30 seconds is the recommended time for avoiding open connections without authenticate
[SSH Hardening - 8: Wrong Grace Time {PCI_DSS: 2.2.4}] [any] [8]
f:$sshd_file -> !r:^\s*LoginGraceTime\s+30\s*$;


# MaxAuthTries 4
# The MaxAuthTries parameter specifices the maximum number of authentication attempts permitted per connection. Once the number of failures reaches half this value, additional failures are logged.
# This should be set to 4.
[SSH Hardening - 9: Wrong Maximum number of authentication attempts {PCI_DSS: 2.2.4}] [any] [9]
f:$sshd_file -> !r:^\s*MaxAuthTries\s+4\s*$;
```
Archivo **/var/containers/wazuh/wazuh/var/ossec/etc/shared/cis_debian_linux_rcl.txt**

```txt
# OSSEC Linux Audit - (C) 2008 Daniel B. Cid - dcid@ossec.net
#
# PCI Tagging by Wazuh <ossec@wazuh.com>.
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Debian/Ubuntu
# Based on Center for Internet Security Benchmark for Debian Linux v1.0

# Main one. Only valid for Debian/Ubuntu.
[CIS - Testing against the CIS Debian Linux Benchmark v1.0] [all required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/debian_version;
f:/proc/sys/kernel/ostype -> Linux;


# Section 1.4 - Partition scheme.
[CIS - Debian Linux - 1.4 - Robust partition scheme - /tmp is not on its own partition {CIS: 1.4 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:/tmp;

[CIS - Debian Linux - 1.4 - Robust partition scheme - /opt is not on its own partition {CIS: 1.4 Debian Linux}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/opt;
f:/etc/fstab -> !r:/opt;

[CIS - Debian Linux - 1.4 - Robust partition scheme - /var is not on its own partition {CIS: 1.4 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:/var;


# Section 2.3 - SSH configuration
[CIS - Debian Linux - 2.3 - SSH Configuration - Protocol version 1 enabled {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

[CIS - Debian Linux - 2.3 - SSH Configuration - IgnoreRHosts disabled {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

[CIS - Debian Linux - 2.3 - SSH Configuration - Empty passwords permitted {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;

[CIS - Debian Linux - 2.3 - SSH Configuration - Host based authentication enabled {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

[CIS - Debian Linux - 2.3 - SSH Configuration - Root login allowed {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;


# Section 2.4 Enable system accounting
#[CIS - Debian Linux - 2.4 - System Accounting - Sysstat not installed {CIS: 2.4 Debian Linux}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
#f:!/etc/default/sysstat;
#f:!/var/log/sysstat;

#[CIS - Debian Linux - 2.4 - System Accounting - Sysstat not enabled {CIS: 2.4 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
#f:!/etc/default/sysstat;
#f:/etc/default/sysstat -> !r:^# && r:ENABLED="false";


# Section 2.5 Install and run Bastille
#[CIS - Debian Linux - 2.5 - System harderning - Bastille is not installed {CIS: 2.5 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
#f:!/etc/Bastille;


# Section 2.6 Ensure sources.list Sanity
[CIS - Debian Linux - 2.6 - Sources list sanity - Security updates not enabled {CIS: 2.6 Debian Linux} {PCI_DSS: 6.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:!/etc/apt/sources.list;
f:!/etc/apt/sources.list -> !r:^# && r:http://security.debian|http://security.ubuntu;


# Section 3 - Minimize inetd services
[CIS - Debian Linux - 3.3 - Telnet enabled on inetd {CIS: 3.3 Debian Linux} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:telnet;

[CIS - Debian Linux - 3.4 - FTP enabled on inetd {CIS: 3.4 Debian Linux} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:/ftp;

[CIS - Debian Linux - 3.5 - rsh/rlogin/rcp enabled on inetd {CIS: 3.5 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:shell|login;

[CIS - Debian Linux - 3.6 - tftpd enabled on inetd {CIS: 3.6 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:tftp;

[CIS - Debian Linux - 3.7 - imap enabled on inetd {CIS: 3.7 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:imap;

[CIS - Debian Linux - 3.8 - pop3 enabled on inetd {CIS: 3.8 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:pop;

[CIS - Debian Linux - 3.9 - Ident enabled on inetd {CIS: 3.9 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:ident;


# Section 4 - Minimize boot services
[CIS - Debian Linux - 4.1 - Disable inetd - Inetd enabled but no services running {CIS: 4.1 Debian Linux} {PCI_DSS: 2.2.2}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
p:inetd;
f:!/etc/inetd.conf -> !r:^# && r:wait;

[CIS - Debian Linux - 4.3 - GUI login enabled {CIS: 4.3 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inittab -> !r:^# && r:id:5;

[CIS - Debian Linux - 4.6 - Disable standard boot services - Samba Enabled {CIS: 4.6 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/samba;

[CIS - Debian Linux - 4.7 - Disable standard boot services - NFS Enabled {CIS: 4.7 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/nfs-common;
f:/etc/init.d/nfs-user-server;
f:/etc/init.d/nfs-kernel-server;

[CIS - Debian Linux - 4.9 - Disable standard boot services - NIS Enabled {CIS: 4.9 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/nis;

[CIS - Debian Linux - 4.13 - Disable standard boot services - Web server Enabled {CIS: 4.13 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/apache;
f:/etc/init.d/apache2;

[CIS - Debian Linux - 4.15 - Disable standard boot services - DNS server Enabled {CIS: 4.15 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/bind;

[CIS - Debian Linux - 4.16 - Disable standard boot services - MySQL server Enabled {CIS: 4.16 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/mysql;

[CIS - Debian Linux - 4.16 - Disable standard boot services - PostgreSQL server Enabled {CIS: 4.16 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/postgresql;

[CIS - Debian Linux - 4.17 - Disable standard boot services - Webmin Enabled {CIS: 4.17 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/webmin;

[CIS - Debian Linux - 4.18 - Disable standard boot services - Squid Enabled {CIS: 4.18 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/squid;


# Section 5 - Kernel tuning
[CIS - Debian Linux - 5.1 - Network parameters - Source routing accepted {CIS: 5.1 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

[CIS - Debian Linux - 5.1 - Network parameters - ICMP broadcasts accepted {CIS: 5.1 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

[CIS - Debian Linux - 5.2 - Network parameters - IP Forwarding enabled {CIS: 5.2 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;


# Section 7 - Permissions
[CIS - Debian Linux - 7.1 - Partition /var without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/var && !r:nodev;

[CIS - Debian Linux - 7.1 - Partition /tmp without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/tmp && !r:nodev;

[CIS - Debian Linux - 7.1 - Partition /opt without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/opt && !r:nodev;

[CIS - Debian Linux - 7.1 - Partition /home without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/home && !r:nodev ;

[CIS - Debian Linux - 7.2 - Removable partition /media without 'nodev' set {CIS: 7.2 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

[CIS - Debian Linux - 7.2 - Removable partition /media without 'nosuid' set {CIS: 7.2 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

[CIS - Debian Linux - 7.3 - User-mounted removable partition /media {CIS: 7.3 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && r:user;


# Section 8 - Access and authentication
[CIS - Debian Linux - 8.8 - LILO Password not set {CIS: 8.8 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/lilo.conf -> !r:^# && !r:restricted;
f:/etc/lilo.conf -> !r:^# && !r:password=;

[CIS - Debian Linux - 8.8 - GRUB Password not set {CIS: 8.8 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/boot/grub/menu.lst -> !r:^# && !r:password;

[CIS - Debian Linux - 9.2 - Account with empty password present {CIS: 9.2 Debian Linux} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - Debian Linux - 13.11 - Non-root account with uid 0 {CIS: 13.11 Debian Linux} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;
```

Finalmente para crear el contenedor correspondiente al API de Wazuh ejecutamos el siguiente comando:

```bash
docker run --name=wazuh -d --link=logstash_wazuh:logstash -p 1514:1514/udp -p 1515:1515 -p 514:514/udp -p 55000:55000 -v /var/containers/wazuh/wazuh/var/ossec/data:/var/ossec/data:z -v /var/containers/wazuh/wazuh/etc/postfix:/etc/postfix:z -v /var/containers/wazuh/wazuh/etc/filebeat:/etc/filebeat:z -v /var/containers/wazuh/wazuh/wazuh-config-mount/etc/ossec.conf:/wazuh-config-mount/etc/ossec.conf:z -v /var/containers/wazuh/wazuh/etc/filebeat/filebeat.yml:/etc/filebeat/filebeat.yml:z -v /var/containers/wazuh/wazuh/var/ossec/etc/shared/:/var/ossec/etc/shared/:z -v  /var/containers/wazuh/wazuh/var/log/mail.log:/var/log/mail.log:z -v /etc/localtime:/etc/localtime:ro wazuh/wazuh:3.6.1_6.4.2
```

### Instalación de Kibana
El primer paso es acondicionar el servidor creando los volumenes utilizados por Kibana a traves de la ejecución del comando:

```bash
mkdir -p /var/containers/wazuh/elk/kibana/
```
Una vez creado el directorio, es necesario generar el archivo de configuración para Elasticsearch, **/var/containers/wazuh/elk/kibana/kibana.yml**.

Cuyo contenido es el siguiente:

```yml
# =================== kibana: kibana.yml ====================== #
#kibana configuration from kibana-docker.
server.name: kibana
server.host: "0"
elasticsearch.url: http://elasticsearch:9200 #DirecciOn IP del contenedor de elasticsearch
```
Finalmente para crear el contenedor correspondiente a Kibana ejecutamos el siguiente comando:

```bash
docker run --name=kibana_wazuh --link=elasticsearch_wazuh:elasticsearch --link=logstash_wazuh:logstash --link=wazuh:wazuh -p 5601:5601 -d -v /var/containers/wazuh/elk/kibana/kibana.yml:/usr/share/kibana/config/kibana.yml:z -v /etc/localtime:/etc/localtime:ro wazuh/wazuh-kibana:3.6.1_6.4.2
```

**Hasta este punto el servidor de Wazuh ya se encuentra corriendo, de tal forma que al entrar en el navegador a http://localhost:5601 podremos ver desplegado el dashboard de Kiabana con el modulo de Wazuh integrado**