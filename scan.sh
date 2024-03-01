#!/bin/bash

domains_file="/root/tools/domains.txt"

if [ ! -f "$domains_file" ]; then
    echo "El archivo de dominios $domains_file no existe."
    exit 1
fi

while IFS= read -r domain; do
    bash ~/tools/ElKraken/ElKrakenTool.sh -domain "$domain" -recon -wayback -nuclei_cves -nuclei_dlogins -nuclei_panels -nuclei_exposures -nuclei_misc -nuclei_misconfig -nuclei_takeovers -nuclei_tech -nuclei_vuln -cors -nmap -crlf -or -output
    wait
    sleep 5
done < "$domains_file"
