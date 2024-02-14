#!/bin/bash
sudo apt update
sudo aptget install -y tmux
sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y jq
sudo apt-get install -y ruby-full
sudo apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-get install -y python-setuptools
sudo apt-get install -y libldns-dev
sudo apt-get install -y python3-pip
sudo apt-get install -y python-pip
sudo apt-get install -y python-dnspython
sudo apt-get install -y git
sudo apt-get install -y rename
sudo apt-get install -y xargs
sudo apt-get install -y chromium chromium-l10n
sudo apt-get install -y golang
apt install -y libpcap-dev
apt install -y tmux
apt install -y dnsutils
apt install -y curl
apt-get install -y nmap
pip3 install dirsearch

pip install colored
pip3 install colored
pip3 install uro
pip3 install --break-system-packages uro
pip3 install requests

mkdir /root/tools

git clone https://github.com/projectdiscovery/nuclei-templates

git clone https://github.com/udhos/update-golang /root/tools/update-golang
sudo bash /root/tools/update-golang/update-golang.sh

git clone https://github.com/aboul3la/Sublist3r.git /root/tools/Sublist3r
cd /root/tools/Sublist3r*
pip3 install -r requirements.txt

git clone https://github.com/maurosoria/dirsearch.git /root/tools/dirsearch

git clone https://github.com/rockysec/customscripts /root/tools/customscripts

git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /root/tools/sqlmap

git clone https://github.com/s0md3v/Corsy /root/tools/Corsy

git clone https://github.com/danielmiessler/SecLists.git /root/tools/SecLists

cd /root/tools/SecLists/Discovery/DNS/
cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt

curl -L -O https://github.com/projectdiscovery/httpx/releases/download/v1.0.3/httpx_1.0.3_linux_amd64.tar.gz
tar -xzvf httpx_1.0.3_linux_amd64.tar.gz
mv httpx /usr/local/bin/

curl -L -O https://github.com/projectdiscovery/nuclei/releases/download/v2.5.4/nuclei_2.5.4_linux_amd64.zip
unzip nuclei_2.5.4_linux_amd64.zip
mv nuclei /usr/bin/
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update
nuclei -update-templates

git clone https://github.com/dwisiswant0/crlfuzz.git /root/tools/crlfuzz
go build /root/tools/crlfuzz/cmd/crlfuzz/main.go
mv /root/tools/crlfuzz/cmd/crlfuzz/crlfuzz /usr/bin/crlfuzz

curl -L -O https://github.com/projectdiscovery/subfinder/releases/download/v2.4.5/subfinder_2.4.5_linux_386.tar.gz
tar -xzvf subfinder_2.4.5_linux_386.tar.gz
cp subfinder /usr/local/bin/

cd /root
git clone https://github.com/1ndianl33t/Gf-Patterns /root/Gf-Patterns
mkdir .gf
mv /root/Gf-Patterns/*.json /root/.gf

GO111MODULE=on go get github.com/tomnomnom/anew@latest
GO111MODULE=on go get github.com/tomnomnom/gf@latest
GO111MODULE=on go get github.com/tomnomnom/qsreplace@latest
GO111MODULE=on go get github.com/tomnomnom/httpx@latest
GO111MODULE=on go get github.com/tomnomnom/waybackurls@latest
nuclei -update-templates
sudo cp /root/go/bin/* /usr/bin
echo -e "\nHappy Hacking!\n"
