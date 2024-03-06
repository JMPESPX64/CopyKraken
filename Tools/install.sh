#!/bin/bash
sudo apt update
sudo apt-get install -y tmux
sudo apt install -y libcurl4-openssl-dev
sudo apt install -y libssl-dev
sudo apt install -y jq
sudo apt install -y ruby-full
sudo apt install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt install -y build-essential libssl-dev libffi-dev python-dev
sudo apt install -y python-setuptools
sudo apt install -y libldns-dev
sudo apt install -y python3-pip
sudo apt install -y python-pip
sudo apt install -y python3-dnspython
sudo apt install -y git
sudo apt install -y rename
sudo apt install -y xargs
sudo apt install -y chromium chromium-l10n
sudo apt install -y golang
apt install -y libpcap-dev
apt install -y tmux
apt install -y dnsutils
apt install -y curl
apt install -y nmap
apt install dos2unix
pip3 install dirsearch

pip install colored
pip3 install colored
pip3 install uro
pip3 install --break-system-packages uro
pip3 install requests

mkdir /root/tools

git clone https://github.com/projectdiscovery/nuclei-templates

git clone https://github.com/rockysec/customscripts /root/tools/customscripts

git clone https://github.com/udhos/update-golang /root/tools/update-golang
sudo bash /root/tools/update-golang/update-golang.sh

git clone https://github.com/aboul3la/Sublist3r.git /root/tools/Sublist3r
cd /root/tools/Sublist3r*
pip3 install -r requirements.txt

git clone https://github.com/maurosoria/dirsearch.git /root/tools/dirsearch

git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /root/tools/sqlmap

git clone https://github.com/s0md3v/Corsy /root/tools/Corsy

git clone https://github.com/danielmiessler/SecLists.git /root/tools/SecLists

cd /root/tools/SecLists/Discovery/DNS/
cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt

# Install httpx
curl -L -O https://github.com/projectdiscovery/httpx/releases/download/v1.0.3/httpx_1.0.3_linux_amd64.tar.gz
tar -xzvf httpx_1.0.3_linux_amd64.tar.gz
mv httpx /usr/local/bin/

# Install crlfuzz
curl -sSfL https://git.io/crlfuzz | sh -s -- -b /usr/local/bin

# Install subfinder
#curl -L -O https://github.com/projectdiscovery/subfinder/releases/download/v2.4.5/subfinder_2.4.5_linux_386.tar.gz
#tar -xzvf subfinder_2.4.5_linux_386.tar.gz
#cp subfinder /usr/local/bin/

# Install nuclei
cd /root/tools/
curl -L -O https://github.com/projectdiscovery/nuclei/releases/download/v3.1.10/nuclei_3.1.10_linux_amd64.zip
unzip nuclei_3.1.10_linux_amd64.zip
mv nuclei /usr/bin/
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update

# Install Gf-Patterns
cd /root
git clone https://github.com/1ndianl33t/Gf-Patterns /root/Gf-Patterns
mkdir .gf
mv /root/Gf-Patterns/*.json /root/.gf

GO111MODULE=on go get github.com/tomnomnom/anew@latest
GO111MODULE=on go get github.com/tomnomnom/gf@latest
GO111MODULE=on go get github.com/tomnomnom/qsreplace@latest
GO111MODULE=on go get github.com/tomnomnom/httpx@latest
GO111MODULE=on go get github.com/tomnomnom/waybackurls@latest
GO111MODULE=on go get github.com/hahwul/dalfox/v2@latest
GO111MODULE=on go get github.com/lc/gau/v2/cmd/gau@latest
GO111MODULE=on go get github.com/Emoe/kxss@latest
GO111MODULE=on go get github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
GO111MODULE=on go get github.com/hahwul/dalfox/v2@latest
GO111MODULE=on go get github.com/tomnomnom/assetfinder@latest
GO111MODULE=on go get github.com/projectdiscovery/katana/cmd/katana@latest
export GO111MODULE=off
go install -v github.com/owasp-amass/amass/v4/...@master
export GO111MODULE=on
nuclei -update-templates
sudo cp /root/go/bin/* /usr/bin
echo -e "\nHappy Hacking!\n"
