#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
sudo apt update
sudo apt install -y libcurl4-openssl-dev tar
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
sudo apt install -y libpcap-dev
sudo apt install -y tmux
sudo apt install -y dnsutils
sudo apt install -y curl
sudo apt install -y nmap
sudo apt install -y dos2unix
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
cd /root/tools
latest_version=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link="https://github.com/projectdiscovery/subfinder/releases/download/${latest_version}/subfinder_$(echo $latest_version | tr -d 'v')_linux_amd64.zip"
curl -LO $download_link
unzip subfinder_$(echo $latest_version | tr -d 'v')_linux_amd64.zip
cp subfinder /usr/bin/subfinder

# Install nuclei
cd /root/tools/
curl -L -O https://github.com/projectdiscovery/nuclei/releases/download/v3.1.10/nuclei_3.1.10_linux_amd64.zip
unzip nuclei_3.1.10_linux_amd64.zip
mv nuclei /usr/bin/
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update

# Install amass
cd /root/tools
latest_version=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link="https://github.com/owasp-amass/amass/releases/download/${latest_version}/amass_Linux_amd64.zip"
curl -LO $download_link
unzip -o amass_Linux_amd64.zip
cp amass_Linux_amd64/amass /usr/local/bin/amass

# Install dalfox
cd /root/tools
latest_version=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link="https://github.com/hahwul/dalfox/releases/download/${latest_version}/dalfox_$(echo $latest_version | tr -d 'v')_linux_amd64.tar.gz"
curl -LO $download_link
tar -xf dalfox_$(echo $latest_version | tr -d 'v')_linux_amd64.tar.gz
mv dalfox /usr/local/bin/dalfox

# Install GAU
cd /root/tools
latest_version=$(curl -s https://api.github.com/repos/lc/gau/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link="https://github.com/lc/gau/releases/download/${latest_version}/gau_$(echo $latest_version | tr -d 'v')_linux_amd64.tar.gz"
curl -LO $download_link
tar -xf gau_$(echo $latest_version | tr -d 'v')_linux_amd64.tar.gz
cp gau /usr/bin/gau

# Install Katana
cd /root/tools
latest_version=$(curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link="https://github.com/projectdiscovery/katana/releases/download/${latest_version}/katana_$(echo $latest_version | tr -d 'v')_linux_amd64.zip"
curl -LO $download_link
unzip -o katana_$(echo $latest_version | tr -d 'v')_linux_amd64.zip
cp katana /usr/bin/katana

# Install Gf-Patterns
cd /root
git clone https://github.com/1ndianl33t/Gf-Patterns /root/Gf-Patterns
mkdir .gf
mv /root/Gf-Patterns/*.json /root/.gf

go install -v github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/KathanP19/Gxss@latest
go install github.com/tomnomnom/assetfinder@latest
nuclei -update-templates
sudo cp /root/go/bin/* /usr/bin


