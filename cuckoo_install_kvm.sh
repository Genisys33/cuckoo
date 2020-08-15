#!/bin/bash

function getValue(){
        cat $ENVFILE | grep "^$1=" | cut -d "=" -f 2 | head -n 1 | tr -d "\n"
}

function param(){
        CONF_HYPERVISOR=/home/cuckoo/.cuckoo/conf/$CUCKOO_HYPERVISOR.conf
        $PREFIX perl -p -i -e "s/(?<=label =).+/ $CUCKOO_GUEST_VMNAME/g" $CONF_HYPERVISOR
        $PREFIX perl -p -i -e "s/(?<=^ip =).+/ $CUCKOO_GUEST_IP/g" $CONF_HYPERVISOR
        $PREFIX perl -p -i -e "s/(?<=snapshot =).+/ $CUCKOO_GUEST_SNAPSHOT/g" $CONF_HYPERVISOR


        CONF_CUCKOO=/home/cuckoo/.cuckoo/conf/cuckoo.conf
        $PREFIX perl -p -i -e "s/(?<=^version_check =).+/ no/g" $CONF_CUCKOO
        $PREFIX perl -p -i -e "s/(?<=^ip =).+/ $CUCKOO_RESULTSERVER_IP/g" $CONF_CUCKOO
        $PREFIX perl -p -i -e "s/(?<=ignore_vulnerabilities =).+/ yes/g" $CONF_CUCKOO
        $PREFIX perl -p -i -e "s/(?<=machinery =).+/ $CUCKOO_HYPERVISOR/g" $CONF_CUCKOO
		
		$PREFIX chown cuckoo: $CONF_CUCKOO $CONF_HYPERVISOR
}

INIT_PATH=$(pwd)

# Vérification de la présence de quelques variables indispensables à la configuration de cuckoo.
ENVFILE=`dirname $0`/envfile
test -f "$ENVFILE"
if [ $? -ne 0 ];then
        # If envfile doesn't exist, create it and exit. User must fill it properly and re-run installation
        cat > "$ENVFILE" << EOF
CUCKOO_HYPERVISOR=kvm
CUCKOO_GUEST_VMNAME=cuckoo1
CUCKOO_GUEST_IP=192.168.56.101
CUCKOO_GUEST_SNAPSHOT=CUCKOO_READY
CUCKOO_RESULTSERVER_IP=0.0.0.0
EOF
        echo "$ENVFILE has been created, fill it properly and re-run installation."
        exit 1
fi


CUCKOO_HYPERVISOR=$(getValue CUCKOO_HYPERVISOR)
CUCKOO_GUEST_VMNAME=$(getValue CUCKOO_GUEST_VMNAME)
CUCKOO_GUEST_IP=$(getValue CUCKOO_GUEST_IP)
CUCKOO_GUEST_SNAPSHOT=$(getValue CUCKOO_GUEST_SNAPSHOT)
CUCKOO_RESULTSERVER_IP=$(getValue CUCKOO_RESULTSERVER_IP)

# On commence par vérifier l'utilisateur courant, si c'est root alors pas besoin d'utiliser la commande sudo pour les commandes spécifiques
PREFIX=""

if [ $USER != "root" ];then
        # On vérifie si sudo est installé
        which sudo > /dev/null
        if [ $? -ne 0 ];then
                echo "sudo does not seem to be installed, to execute this script as non-root user you must install sudo, or run it as 'root'..."
                exit 1
        fi

        # On part du principe que si sudo est installé et que l'on est connecté en tant que simple utilisateur, le fichier /etc/sudoers a déjà été configuré pour que cet
        # utilisateur puisse utiliser sudo sans password (type box vagrant)

        PREFIX="sudo "

fi

$PREFIX useradd -m cuckoo --shell /bin/bash
echo "cuckoo ALL=(ALL) NOPASSWD: ALL" | $PREFIX tee -a /etc/sudoers
echo "cuckoo:cuckoo" | $PREFIX chpasswd


$PREFIX apt update && $PREFIX apt install -y \
        gnupg2 \
        $PREFIX \
        unzip \
        wget

# Ajout du repository mongodb
wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | $PREFIX apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | $PREFIX tee /etc/apt/sources.list.d/mongodb.list

# Installation des paquets nécessaires
$PREFIX apt update && $PREFIX apt install -y \
    apparmor-utils \
    automake \
    bison \
    bridge-utils \
    cpu-checker \
    curl \
    flex \
    gcc \
    git \
    libcap2-bin \
    libffi-dev \
    libfuzzy-dev \
    libjansson-dev \
    libjpeg-dev \
    libmagic-dev \
    libssl-dev \
    libtool \
    libvirt0 \
    libvirt-dev \
    make \
    mongodb-org \
    python \
    python-dev \
    python-libvirt \
    python-pip \
    python-setuptools \
    python-ssdeep \
    python-virtualenv \
    qemu-kvm \
    ssdeep \
    swig \
    tcpdump \
    unzip \
    virtinst \
    virt-manager \
    zlib1g-dev

## Configuration KVM
if [ $CUCKOO_HYPERVISOR = "kvm" ];then
$PREFIX virsh net-autostart default
$PREFIX virsh net-start default
CUCKOO_RESULTSERVER_IP=`$PREFIX ifconfig virbr0 | grep netmask | awk -F " " '{print $2}'`
fi

$PREFIX aa-disable /usr/sbin/tcpdump
$PREFIX setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
$PREFIX getcap /usr/sbin/tcpdump

$PREFIX usermod -a -G kvm cuckoo
$PREFIX usermod -a -G libvirt cuckoo
$PREFIX usermod -a -G libvirt-qemu cuckoo


# Installation de YARA
cd /tmp/
wget https://github.com/VirusTotal/yara/archive/v3.11.0.zip
unzip -o v3.11.0.zip
cd yara-3.11.0
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
$PREFIX make install
echo "========="
make check
cd $OLDPWD

$PREFIX pip install \
    pip \
    pydeep \
    "weasyprint==0.39" \
    yara-python

$PREFIX systemctl enable mongod
$PREFIX systemctl start mongod


############### Validé jusqu'ici


# ===================
# CUCKOO INSTALLATION
# ===================

$PREFIX chmod 705 /opt/
$PREFIX mkdir /opt/cuckoo 2>/dev/null
$PREFIX chown -R cuckoo: /opt/cuckoo
sudo -u cuckoo -- sh -c '
cd /opt/
virtualenv cuckoo
. cuckoo/bin/activate
pip install -U pip setuptools
pip install -U cuckoo
pip install -U distorm3
pip install -U libvirt-python==5.0
pip install -U yara-python
pip install -U weasyprint==0.39
echo "================== debug 1 ============"
echo "----> cuckoo -d"
cuckoo -d
'

echo "----> cuckoo community"
sudo -u cuckoo -- sh -c '
cd /opt/; virtualenv cuckoo 
. cuckoo/bin/activate
cuckoo community
'

sudo -u cuckoo -- sh -c '
cd /opt/; virtualenv cuckoo 
. cuckoo/bin/activate
pip install git+https://github.com/volatilityfoundation/volatility.git
'

# Création des scripts de démarrage

SYSTEMD="/lib/systemd/system"

$PREFIX cp $INIT_PATH/systemd/cuckoo.service $SYSTEMD
$PREFIX cp $INIT_PATH/systemd/cuckooweb.service $SYSTEMD

$PREFIX perl -p -i -e "s/(?<=^User=).+/ cuckoo/g" $SYSTEMD/cuckoo.service
$PREFIX perl -p -i -e "s/(?<=^Group=).+/ cuckoo/g" $SYSTEMD/cuckoo.service

$PREFIX perl -p -i -e "s/(?<=^User=).+/ cuckoo/g" $SYSTEMD/cuckooweb.service
$PREFIX perl -p -i -e "s/(?<=^Group=).+/ cuckoo/g" $SYSTEMD/cuckooweb.service

$PREFIX cp $INIT_PATH/bin/cuckoo.sh /opt/
$PREFIX cp $INIT_PATH/bin/cuckooweb.sh /opt/
$PREFIX chown cuckoo: /opt/cuckoo.sh
$PREFIX chown cuckoo: /opt/cuckooweb.sh

$PREFIX cp $INIT_PATH/conf/* /home/cuckoo/.cuckoo/conf

# Exécution de cuckoo et cuckooweb au démarrage du système
$PREFIX systemctl daemon-reload
$PREFIX systemctl enable cuckoo
$PREFIX systemctl enable cuckooweb

param

sudo -u cuckoo -- sh -c "cat > /home/cuckoo/.cuckoo/conf/reporting.conf << EOF
# Enable or disable the available reporting modules [on/off].
# If you add a custom reporting module to your Cuckoo setup, you have to add
# a dedicated entry in this file, or it won't be executed.
# You can also add additional options under the section of your module and
# they will be available in your Python class.

[feedback]
# Automatically report errors that occurred during an analysis. Requires the
# Cuckoo Feedback settings in cuckoo.conf to have been filled out properly.
enabled = no

[jsondump]
enabled = yes
indent = 4
calls = yes

[singlefile]
# Enable creation of report.html and/or report.pdf?
enabled = yes
# Enable creation of report.html?
html = no
# Enable creation of report.pdf?
pdf = yes

[misp]
enabled = no
url =
apikey =

# The various modes describe which information should be submitted to MISP,
# separated by whitespace. Available modes: maldoc ipaddr hashes url.
mode = maldoc ipaddr hashes url

distribution = 0
analysis = 0
threat_level = 4

# The minimum Cuckoo score for a MISP event to be created
min_malscore = 0

tag = Cuckoo
upload_sample = no

[mongodb]
enabled = yes
host = 127.0.0.1
port = 27017
db = cuckoo
store_memdump = yes
paginate = 100
# MongoDB authentication (optional).
username =
password =

[elasticsearch]
enabled = yes
# Comma-separated list of ElasticSearch hosts. Format is IP:PORT, if port is
# missing the default port is used.
# Example: hosts = 127.0.0.1:9200, 192.168.1.1:80
hosts = 10.1.1.11
# Increase default timeout from 10 seconds, required when indexing larger
# analysis documents.
timeout = 300
# Set to yes if we want to be able to search every API call instead of just
# through the behavioral summary.
calls = no
# Index of this Cuckoo instance. If multiple Cuckoo instances connect to the
# same ElasticSearch host then this index (in Moloch called \"instance\") should
# be unique for each Cuckoo instance.
index = cuckoo

# Logging time pattern.  This sets how elasticsearch creates indexes
# by default it is yearly in most instances this will be sufficient
# valid options: yearly, monthly, daily
index_time_pattern = yearly

# Cuckoo node name in Elasticsearch to identify reporting host. Can be useful
# for automation and while referring back to correct Cuckoo host.
cuckoo_node =

[moloch]
enabled = no
# If the Moloch web interface is hosted on a different IP address than the
# Cuckoo Web Interface then you'll want to override the IP address here.
host =
# If you wish to run Moloch in http (insecure) versus https (secure) mode,
# set insecure to yes.
insecure = no

# Following are various configurable settings. When in use of a recent version
# of Moloch there is no need to change any of the following settings as they
# represent the defaults.
moloch_capture = /data/moloch/bin/moloch-capture
conf = /data/moloch/etc/config.ini
instance = cuckoo

[notification]
# Notification module to inform external systems that analysis is finished.
# You should consider keeping this as very last reporting module.
enabled = no

# External service URL where info will be POSTed.
# example : https://my.example.host/some/destination/url
url =

# Cuckoo host identifier - can be hostname.
# for example : my.cuckoo.host
identifier =

[mattermost]
enabled = no

# Mattermost webhook URL.
# example : https://my.mattermost.host/hooks/yourveryrandomkey
url =

# Cuckoo host URL to make analysis ID clickable.
# example : https://my.cuckoo.host/
myurl =

# Username to show when posting message
username = cuckoo

# What kind of data to show apart from default.
# Show virustotal hits.
show_virustotal = no

# Show matched cuckoo signatures.
show_signatures = no

# Show collected URL-s by signature \"network_http\".
show_urls = no

# Hide filename and create hash of it
hash_filename = no
# Hide URL and create hash of it
hash_url = no

EOF"

# Lancement des services
$PREFIX systemctl start cuckoo
$PREFIX systemctl start cuckooweb
