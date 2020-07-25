#!/bin/bash

function pause(){
	echo "Press a key to continue..."
	read key
}

function waitingOnline(){
	online=1
	TRY=1
	MAX_TRIES=24

	while [ $online == 1 ] && [ $TRY -le $MAX_TRIES ];do
		echo "[$TRY/$MAX_TRIES] Waiting 192.168.56.101 to be online..."
		ping 192.168.56.101 -c 1 >/dev/null 2>&1
		online=$?
		TRY=$(( TRY + 1))
		sleep 5
	done

	if [ $online -eq 0 ];then
		echo "192.168.56.101 is online"
		return 0
	else
		echo "Max tries reach :("
		return 1
	fi
}

# ================
# ===== MAIN =====
# ================

INIT_PATH=$(pwd)

# Un chemin vers l'OVA à importer (cuckoo guest) peut être fournit en paramètre du script.
# Il peut correspondre soit à un chemin vers un fichier local, soit à un lien http(s)://
# Il n'est pas obligatoire de le fournir. Si l'OVA n'est pas fournit au moment de l'installation de cuckoo, il faudra
# bien évidemment l'importer plus tard pour effectuer les analyses.
OVA=$1

# Pour pouvoir installer virtualbox depuis leur miroir
sudo apt update && sudo apt install -y gnupg2

# Ajout du repository de virtualbox
echo "deb http://download.virtualbox.org/virtualbox/debian buster contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O - | sudo apt-key add -
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O - | sudo apt-key add -

# Ajout du repository mongodb
wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | sudo tee /etc/apt/sources.list.d/mongodb.list

# Installation des paquets nécessaires
sudo apt update

sudo apt install -y \
    apparmor-utils \
    automake \
    bison \
    curl \
    flex \
    gcc \
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
    python-pip \
    python-setuptools \
    python-ssdeep \
    python-virtualenv \
    ssdeep \
    swig \
    tcpdump \
    unzip \
    virtualbox-6.1 \
    zlib1g-dev

# Installation de l'extention pack de virtualbox --> Afin d'éviter des problème d'import d'OVA liés aux ports USB
LatestVirtualBoxVersion=$(wget -qO - http://download.virtualbox.org/virtualbox/LATEST-STABLE.TXT)
wget "http://download.virtualbox.org/virtualbox/${LatestVirtualBoxVersion}/Oracle_VM_VirtualBox_Extension_Pack-${LatestVirtualBoxVersion}.vbox-extpack"
echo "y" | sudo VBoxManage extpack install --replace Oracle_VM_VirtualBox_Extension_Pack-${LatestVirtualBoxVersion}.vbox-extpack
rm "Oracle_VM_VirtualBox_Extension_Pack-${LatestVirtualBoxVersion}.vbox-extpack"

sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo getcap /usr/sbin/tcpdump

# Installation de YARA
echo "========="
cd /tmp/
wget https://github.com/VirusTotal/yara/archive/v3.11.0.zip
unzip v3.11.0.zip
cd yara-3.11.0
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
make install
echo "========="
make check
cd $OLDPWD
 
pip install \
    pip \
    pydeep \
    "weasyprint==0.39" \
    yara-python
 

# useradd -m cuckoo --shell /bin/bash
# usermod -a -G vboxusers cuckoo
# echo "cuckoo:cuckoo" | chpasswd


# Création du réseau privé dans lequel sera intégré le(s) GUEST
sudo VBoxManage hostonlyif create
sudo VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

sudo systemctl enable mongod
sudo systemctl start mongod

# ===================
# CUCKOO GUEST IMPORT
# ===================

if [ "$OVA" == "" ];then
	echo "Aucun OVA à importer"
else
	echo "$OVA" | grep "^http*://" > /dev/null
	if [ $? -eq 0 ];then
		# !!! Attention, pas de contrôle sur l'espace libre disponible sur le système de fichier. Un GUEST WIN7 fait au moins 10Go...
		echo "Téléchargement de l'OVA"
		wget "$OVA" -O /tmp/cuckoo1.ova
		OVA="/tmp/cuckoo1.ova"
	fi

	# OVA import to VirtualBox
	cd "$INIT_PATH"
	echo "Importing appliance $OVA..."
	vboxmanage import "./$OVA" --vsys 0 --vmname cuckoo1

	# Setting network interface in the correct lan
	vboxmanage modifyvm "cuckoo1" --nic1 hostonly --hostonlyadapter1 vboxnet0

	# Start VM et create a hot-snapshot
	VBoxManage startvm --type headless "cuckoo1"

	# Waiting for VM pingeable (ready)
	waitingOnline
	if [ $? -eq 0 ];then
		VBoxManage snapshot "cuckoo1" take "default" --pause
		VBoxManage controlvm "cuckoo1" poweroff
		VBoxManage snapshot "cuckoo1" restorecurrent
	else
		echo "You will need to start manually the VM and process to hotsnapshot"
	fi
fi


# ===================
# CUCKOO INSTALLATION
# ===================

cd /opt/
sudo virtualenv cuckoo
. cuckoo/bin/activate
sudo pip install -U pip setuptools
sudo pip install -U cuckoo
sudo pip install -U distorm3
cuckoo community
sudo pip install git+https://github.com/volatilityfoundation/volatility.git

# Création des scripts de démarrage
sudo cp $INIT_PATH/cuckoo.service /lib/systemd/system/
sudo cp $INIT_PATH/cuckooweb.service /lib/systemd/system/

sudo cp $INIT_PATH/cuckoo.sh /opt/
sudo cp $INIT_PATH/cuckooweb.sh /opt/

sudo systemctl daemon-reload
sudo systemctl enable cuckoo
sudo systemctl enable cuckooweb


# On lance 1 fois cuckoo à la main pour finaliser l'installation (créaction de /root/.cuckoo... sur lequel s'appuiera cuckoo web)
/bin/bash /opt/cuckoo.sh

# On replaque le fichier de reporting, activant ainsi la connexion vers mongodb, nécessaire pour cuckoo web
cat > ~/.cuckoo/conf/reporting.conf << EOF

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
enabled = no
# Enable creation of report.html?
html = no
# Enable creation of report.pdf?
pdf = no

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
enabled = no
# Comma-separated list of ElasticSearch hosts. Format is IP:PORT, if port is
# missing the default port is used.
# Example: hosts = 127.0.0.1:9200, 192.168.1.1:80
hosts = 127.0.0.1
# Increase default timeout from 10 seconds, required when indexing larger
# analysis documents.
timeout = 300
# Set to yes if we want to be able to search every API call instead of just
# through the behavioral summary.
calls = no
# Index of this Cuckoo instance. If multiple Cuckoo instances connect to the
# same ElasticSearch host then this index (in Moloch called "instance") should
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

# Show collected URL-s by signature "network_http".
show_urls = no

# Hide filename and create hash of it
hash_filename = no
# Hide URL and create hash of it
hash_url = no
EOF

# Lancement des services
sudo systemctl start cuckoo
sudo systemctl start cuckooweb
