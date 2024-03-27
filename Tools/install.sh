#!/bin/bash
apt update
apt install moreutils -y
apt install sudo -y
sudo apt install -y libcurl4-openssl-dev tar zip unzip
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

pip3 install uro --break-system-packages
pip3 install requests --break-system-packages

# Aquatone
mkdir /root/tools/aquatone_dir
cd /root/tools/aquatone_dir
latest_version_aquatone=$(curl -s https://api.github.com/repos/michenriksen/aquatone/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link_aquatone="https://github.com/michenriksen/aquatone/releases/download/${latest_version_aquatone}/aquatone_linux_amd64_$(echo $latest_version_aquatone | tr -d 'v').zip"
curl -LO $download_link_aquatone
unzip /root/tools/aquatone_linux_amd64_$(echo $latest_version | tr -d 'v').zip
cp /root/tools/aquatone_dir/aquatone /usr/local/bin/aquatone

# Install SecretFinder
git clone https://github.com/m4ll0k/SecretFinder.git /root/tools/secretfinder
cd /root/tools/secretfinder
pip3 install -r requirements.txt --break-system-packages

# Install crlfuzz
curl -sSfL https://git.io/crlfuzz | sh -s -- -b /usr/local/bin

# Install corsy
git clone https://github.com/s0md3v/Corsy /root/tools/Corsy
pip3 install -r /root/tools/Corsy/requirements.txt --break-system-packages

# GF-PATTERNS
mkdir /root/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /root/tools/Gf-Patterns
mv /root/tools/Gf-Patterns/*.json /root/.gf


# Go packages
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/Emoe/kxss@latest
go install -v github.com/tomnomnom/anew@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest

