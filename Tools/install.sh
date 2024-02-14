#!/bin/bash

# Actualizar los repositorios e instalar paquetes esenciales
sudo apt update
sudo apt install -y tmux libcurl4-openssl-dev libssl-dev jq ruby-full build-essential libgmp-dev zlib1g-dev libffi-dev python-dev python-setuptools libldns-dev python3-pip python-pip git rename xargs chromium chromium-l10n golang libpcap-dev dnsutils curl nmap

# Instalar herramientas de Python
pip3 install dirsearch colored uro requests

# Crear directorio de herramientas
mkdir -p ~/tools

# Clonar y actualizar repositorios de herramientas
cd ~/tools || exit
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update-templates

git clone https://github.com/udhos/update-golang
cd update-golang || exit
sudo ./update-golang.sh

git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r || exit
pip install -r requirements.txt

git clone https://github.com/maurosoria/dirsearch.git

git clone https://github.com/rockysec/customscripts

git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git

git clone https://github.com/s0md3v/Corsy

git clone https://github.com/danielmiessler/SecLists.git

cd SecLists/Discovery/DNS/ || exit
head -n -14 dns-Jhaddix.txt > clean-jhaddix-dns.txt

# Instalar httpx
cd ~/tools || exit
curl -L -o httpx.tar.gz https://github.com/projectdiscovery/httpx/releases/download/v1.0.3/httpx_1.0.3_linux_amd64.tar.gz
tar -xzvf httpx.tar.gz
sudo mv httpx /usr/local/bin/

# Instalar nuclei
curl -L -o nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v2.5.4/nuclei_2.5.4_linux_amd64.zip
unzip nuclei.zip
sudo mv nuclei /usr/local/bin/
rm nuclei.zip
nuclei -update

# Instalar crlfuzz
cd ~/tools || exit
git clone https://github.com/dwisiswant0/crlfuzz.git
cd crlfuzz || exit
go build cmd/crlfuzz/main.go
sudo mv crlfuzz /usr/local/bin/

# Instalar subfinder
curl -L -o subfinder.tar.gz https://github.com/projectdiscovery/subfinder/releases/download/v2.4.5/subfinder_2.4.5_linux_386.tar.gz
tar -xzvf subfinder.tar.gz
sudo mv subfinder /usr/local/bin/
rm subfinder.tar.gz

# Configurar Gf-Patterns
cd ~ || exit
git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir -p ~/.gf
mv ~/Gf-Patterns/*.json ~/.gf

# Instalar herramientas de Go
GO111MODULE=on go get -v github.com/tomnomnom/anew
GO111MODULE=on go get -v github.com/tomnomnom/gf
GO111MODULE=on go get -v github.com/tomnomnom/qsreplace
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
GO111MODULE=on go get -v github.com/tomnomnom/waybackurls

# Instalar Nuclei y actualizar las plantillas
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
nuclei -update-templates

# Copiar binarios instalados globalmente
sudo cp ~/go/bin/* /usr/local/bin/
