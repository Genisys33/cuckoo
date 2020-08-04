#!/bin/bash

function getValue(){
	cat $ENVFILE | grep "^$1=" | cut -d "=" -f 2 | head -n 1 | tr -d "\n"
}

function param(){
	CONF_ESX=~/.cuckoo/conf/esx.conf
	perl -p -i -e "s|(?<=esx://).+?(?=/)|$CUCKOO_ESXI_HOST|g" $CONF_ESX
	perl -p -i -e "s/(?<=username =).+/ $CUCKOO_ESXI_USER/g" $CONF_ESX
	perl -p -i -e "s/(?<=password =).+/ $CUCKOO_ESXI_PASSWORD/g" $CONF_ESX
	perl -p -i -e "s/(?<=label =).+/ $CUCKOO_GUEST_VMNAME/g" $CONF_ESX
	perl -p -i -e "s/(?<=^ip =).+/ $CUCKOO_GUEST_IP/g" $CONF_ESX
	perl -p -i -e "s/(?<=snapshot =).+/ $CUCKOO_GUEST_SNAPSHOT/g" $CONF_ESX


	CONF_CUCKOO=~/.cuckoo/conf/cuckoo.conf
	perl -p -i -e "s/(?<=^ip =).+/ $CUCKOO_RESULTSERVER_IP/g" $CONF_CUCKOO
	perl -p -i -e "s/(?<=ignore_vulnerabilities =).+/ yes/g" $CONF_CUCKOO
	perl -p -i -e "s/(?<=machinery =).+/ esx/g" $CONF_CUCKOO
}

INIT_PATH=$(pwd)

# Vérification de la présence de quelques variables indispensables à la configuration de cuckoo.
ENVFILE=`dirname $0`/envfile
test -f "$ENVFILE"
if [ $? -ne 0 ];then
	# If envfile doesn't exist, create it and exit. User must fill it properly and re-run installation
	cat > "$ENVFILE" << EOF
CUCKOO_ESXI_HOST=
CUCKOO_ESXI_USER=
CUCKOO_ESXI_PASSWORD=
CUCKOO_GUEST_VMNAME=
CUCKOO_GUEST_IP=
CUCKOO_GUEST_SNAPSHOT=
CUCKOO_RESULTSERVER_IP=
EOF
	echo "$ENVFILE has been created, fill it properly and re-run installation."
	exit 1
fi


CUCKOO_ESXI_HOST=$(getValue CUCKOO_ESXI_HOST)
CUCKOO_ESXI_USER=$(getValue CUCKOO_ESXI_USER)
CUCKOO_ESXI_PASSWORD=$(getValue CUCKOO_ESXI_PASSWORD)
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
	PREFIX="sudo"
fi


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
    make \
    mongodb-org \
    python \
    python-dev \
    python-libvirt \
    python-pip \
    python-setuptools \
    python-ssdeep \
    python-virtualenv \
    ssdeep \
    swig \
    tcpdump \
    unzip \
    zlib1g-dev


$PREFIX aa-disable /usr/sbin/tcpdump
$PREFIX setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
$PREFIX getcap /usr/sbin/tcpdump

# Installation de YARA
cd /tmp/
wget https://github.com/VirusTotal/yara/archive/v3.11.0.zip
unzip v3.11.0.zip
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


# ===================
# CUCKOO INSTALLATION
# ===================

cd /opt/
$PREFIX virtualenv cuckoo
. cuckoo/bin/activate
$PREFIX pip install -U pip setuptools
$PREFIX pip install -U cuckoo
$PREFIX pip install -U distorm3
echo "================== debug 1 ============"
echo "----> cuckoo -d"
cuckoo -d

echo "----> cuckoo community"
cuckoo community

$PREFIX pip install git+https://github.com/volatilityfoundation/volatility.git

# Création des scripts de démarrage

SYSTEMD="/lib/systemd/system"

$PREFIX cp $INIT_PATH/systemd/cuckoo.service $SYSTEMD
$PREFIX cp $INIT_PATH/systemd/cuckooweb.service $SYSTEMD

$PREFIX perl -p -i -e "s/(?<=^User=).+/ $USER/g" $SYSTEMD/cuckoo.service
$PREFIX perl -p -i -e "s/(?<=^Group=).+/ $USER/g" $SYSTEMD/cuckoo.service

$PREFIX perl -p -i -e "s/(?<=^User=).+/ $USER/g" $SYSTEMD/cuckooweb.service
$PREFIX perl -p -i -e "s/(?<=^Group=).+/ $USER/g" $SYSTEMD/cuckooweb.service

$PREFIX cp $INIT_PATH/bin/cuckoo.sh /opt/
$PREFIX cp $INIT_PATH/bin/cuckooweb.sh /opt/

$PREFIX cp $INIT_PATH/conf/* ~/.cuckoo/conf

# Exécution de cuckoo et cuckooweb au démarrage du système
$PREFIX systemctl daemon-reload
$PREFIX systemctl enable cuckoo
$PREFIX systemctl enable cuckooweb

param

# Lancement des services
$PREFIX systemctl start cuckoo
$PREFIX systemctl start cuckooweb
