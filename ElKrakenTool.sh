#!/bin/bash

domain=$1
notify=true 
directory_data=/root 
tools_dir=$directory_data/tools
mkdir -p $directory_data/$domain/subdomains
mkdir $directory_data/$domain/httpx_info
mkdir $directory_data/$domain/screenshots
mkdir $directory_data/$domain/vulns
mkdir $directory_data/$domain/wayback_urls
mkdir $directory_data/$domain/secrets

function notify {
    if [ "$notify" = true ]
    then
        if [ $(($(date +%s) - lastNotified)) -le 3 ]
        then
            echo "[!] Notifying too quickly, sleeping to avoid skipped notifications..."
            sleep 3
        fi

        # Format string to escape special characters and send message through Telegram API.
        if [ -z "$DOMAIN" ]
        then
            message=`echo -ne "*BugBountyScanner:* $1" | sed 's/[^a-zA-Z 0-9*_]/\\\\&/g'`
        else
            message=`echo -ne "*BugBountyScanner [$DOMAIN]:* $1" | sed 's/[^a-zA-Z 0-9*_]/\\\\&/g'`
        fi
    
        curl -s -X POST "https://api.telegram.org/bot$telegram_api_key/sendMessage" -d chat_id="$telegram_chat_id" -d text="$message" -d parse_mode="MarkdownV2" &> /dev/null
        lastNotified=$(date +%s)
    fi
}

# Find subdomains 
notify "Listing subdomains"
chaos -dL $domain -silent >> $directory_data/$domain/subdomains/subdomains.txt
subfinder -dL $domain -all -silent | anew $directory_data/$domain/subdomains/subdomains.txt
assetfinder --subs-only $domain | anew $directory_data/$domain/subdomains/subdomains.txt 

# Get alive subdomains 
notify "Running httpx"
cat $directory_data/$domain/subdomains/subdomains.txt | httpx -title -tech-detect -status-code -ip -p 80,443,8080,8081,9002,8443,81 >> $directory_data/$domain/httpx_info/httpx_full_info.txt

cat $directory_data/$domain/httpx_info/httpx_full_info.txt | awk '{print $1}' >> $directory_data/$domain/httpx_info/alive_subdomains.txt

# Take screenshots
notify "Taking screenshots"
cat $directory_data/$domain/httpx_info/alive_subdomains.txt | aquatone -out $directory_data/$domain/screenshots

# Subdomains takeover 
notify "Check subdomains takeover with subzy"
subzy run --targets $directory_data/$domain/httpx_info/alive_subdomains.txt --hide_fails >> $directory_data/$domain/vulns/posible_takeover.txt

# XSS
notify "Running gau"
gau --threads 16 --subs --blacklist png,jpg,gif,svg,woff,woff2 $domain >> $directory_data/$domain/wayback_urls/urls.txt
waybackurls $domain | anew $directory_data/$domain/wayback_urls/urls.txt
notify "Running katana"
katana -list $domain -d 5 -jc -silent | anew $directory_data/$domain/secrets/katana.txt
gf xss $directory_data/$domain/wayback_urls/urls.txt >> $directory_data/$domain/wayback_urls/parameter_urls.txt
cat $directory_data/$domain/wayback_urls/parameter_urls.txt | uro | kxss | grep -v "\[\]" >> $directory_data/$domain/vulns/posible_xss.txt

# Find cors
notify "Searching cors"
python3 $tools_dirs/Corsy/corsy.py -i $directory_data/$domain/httpx_info/alive_subdomains.txt -o $directory_data/$domain/vulns/cors.json

# Find crlf
notify "Search for CRLF"
crlfuzz -l $directory_data/$domain/httpx_info/alive_subdomains.txt -o $directory_data/$domain/vulns/crlf.txt
crlfuzz -l $directory_data/$domain/wayback_urls/urls.txt -o $directory_data/$domain/vulns/crlf2.txt
cat $directory_data/$domain/vulns/crlf2.txt | anew $directory_data/$domain/vulns/crlf.txt
rm $directory_data/$domain/vulns/crlf2.txt

# Find secrets
notify "Search secrets"
cat $directory_data/$domain/secrets/katana.txt >> $directory_data/$domain/secrets/js_files.txt
cat $directory_data/$domain/secrets/js_files.txt | while read url ; do
	python3 $tools_dir/secretfinder/SecretFinder.py -i $url -o $directory_data/$domain/secrets/results.html
done

zip -r results.zip $directory_data/$domain
notify "The scan has finished"
