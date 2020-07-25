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


sudo apt update && sudo apt install -y \
	gnupg2 \
	sudo \
	unzip \
	wget

# Ajout du repository mongodb
wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | sudo tee /etc/apt/sources.list.d/mongodb.list

# Installation des paquets nécessaires
sudo apt update && sudo apt install -y \
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


sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo getcap /usr/sbin/tcpdump

# Installation de YARA
cd /tmp/
wget https://github.com/VirusTotal/yara/archive/v3.11.0.zip
unzip v3.11.0.zip
cd yara-3.11.0
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
sudo make install
echo "========="
make check
cd $OLDPWD
 
sudo pip install \
    pip \
    pydeep \
    "weasyprint==0.39" \
    yara-python

sudo systemctl enable mongod
sudo systemctl start mongod


# ===================
# CUCKOO INSTALLATION
# ===================

cd /opt/
sudo virtualenv cuckoo
. cuckoo/bin/activate
sudo pip install -U pip setuptools
sudo pip install -U cuckoo
sudo pip install -U distorm3
echo "================== debug 1 ============"
echo "----> cuckoo -d"
cuckoo -d

echo "----> cuckoo community"
cuckoo community

sudo pip install git+https://github.com/volatilityfoundation/volatility.git

# Création des scripts de démarrage

SYSTEMD="/lib/systemd/system"

sudo cp $INIT_PATH/systemd/cuckoo.service $SYSTEMD
sudo cp $INIT_PATH/systemd/cuckooweb.service $SYSTEMD

sudo perl -p -i -e "s/(?<=^User=).+/ $USER/g" $SYSTEMD/cuckoo.service
sudo perl -p -i -e "s/(?<=^Group=).+/ $USER/g" $SYSTEMD/cuckoo.service

sudo perl -p -i -e "s/(?<=^User=).+/ $USER/g" $SYSTEMD/cuckooweb.service
sudo perl -p -i -e "s/(?<=^Group=).+/ $USER/g" $SYSTEMD/cuckooweb.service

sudo cp $INIT_PATH/bin/cuckoo.sh /opt/
sudo cp $INIT_PATH/bin/cuckooweb.sh /opt/

sudo cp $INIT_PATH/conf/* ~/.cuckoo/conf

# Exécution de cuckoo et cuckooweb au démarrage du système
sudo systemctl daemon-reload
sudo systemctl enable cuckoo
sudo systemctl enable cuckooweb

param

# Lancement des services
sudo systemctl start cuckoo
sudo systemctl start cuckooweb
