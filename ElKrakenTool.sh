#!/bin/bash
############################################
#                                          #
#     Your APITokens and Variables here    #
#                                          #
############################################
dirsearchExtensions="sql,txt,zip,jsp,log,logs,old,tar.gz,gz,tar,tgz,bkp,dump,db,php,php3,php4,php5,,xml,py,asp,aspx,rar,do,1,asmx,rar,key,gpg,asc,pl,js,shtm,shtml,phtm,phtml,jhtml,cfm,cfml,rb,cfg,pdf,doc,docx,xls,xlsx,conf"
tokenSlack="YOUR_TOKEN"
channelSlack="YOUR_CHANNEL"
directory_tools=~/tools
directory_data=/root
ssh_conection="user@ipadd:/folder" ##reemplazar user, ipaddr y folder por los datos de tu servidor repositorio de resultados de escaneo
########################################


function logo {
echo " _____ _       _  ______      _    _  _______ _   _ "
echo "| ____| |     | |/ /  _ \    / \  | |/ / ____| \ | |"
echo "|  _| | |     | ' /| |_) |  / _ \ | ' /|  _| |  \| |"
echo "| |___| |___  | . \|  _ <  / ___ \| . \| |___| |\  |"
echo "|_____|_____| |_|\_\_| \_\/_/   \_\_|\_\_____|_| \_|"
echo ""
}

red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
reset=`tput sgr0`
SECONDS=0
domain=$2
#subreport=
#usage() { echo -e "Usage: $0 -d domain [-e]\n  Select -e to specify excluded domains\n " 1>&2; exit 1; }
#while getopts ":d:e:r:" o; do
#    case "${o}" in
#        d)
#            domain=${OPTARG}
#            ;;

            #### working on subdomain exclusion
#        e)
#            excluded=${OPTARG}
#            ;;
#                r)
#            subreport+=("$OPTARG")
#            ;;
#        *)
#            usage
#            ;;
#    esac
#done

#shift $((OPTIND - 1))
#if [ -z "${domain}" ] && [[ -z ${subreport[@]} ]]; then
#   usage; exit 1;
#fi

function flags {
  echo "${yellow}Argumentos permitidos:"
  echo "-domain <argumento>: Realiza la tarea 1 con el argumento especificado"
  echo "-recon: Realiza validacion dns, urls, etc"
  echo "-wayback: Realiza recopilacion de info en wayback url"
  echo "-dirsearch: Realiza fuzzing de directorios"
  echo "-nuclei_cves: Realiza scaneos con nuclei en busca de vulnerabilidades"
  echo "-nuclei_dlogins: Realiza scaneos con nuclei en busca de Default Logins"
  echo "-nuclei_panels: Realiza scaneos con nuclei en busca de panels de login"
  echo "-nuclei_exposures: Realiza scaneos con nuclei en busca de informacion expuesta"
  echo "-nuclei_misc: Realiza scaneos con nuclei en busca de misc"
  echo "-nuclei_misconfig: Realiza scaneos con nuclei en busca de misconfiguration"
  echo "-nuclei_takeovers: Realiza scaneos con nuclei en busca de posibles dns takeover"
  echo "-nuclei_tech: Realiza scaneos con nuclei en busca de deteccion de tecnologias usadas"
  echo "-nuclei_vuln: Realiza scaneos con nuclei en busca de vulnerabilidades varias"
  echo "-cors: Analiza si las url son vulnerables a Cors"
  echo "-nmap: Realiza scan a todos los puertos de manera agresiva en todos los subdominios"
  echo "-crlf: Realiza busqueda de vulnerabilidad CRLF"
  echo "-or: Realiza la busqueda de Open Redirecg"
  echo "-output: Envia la data recopilada al nodo de ELK"

}

logo
# Verificar si se pasaron argumentos
if [ $# -eq 0 ]; then
  echo "${red}Debe pasar al menos un argumento."
  flags
  exit 1
fi

# Variables de control
domain=""
recon=false
wayback=false
dirsearch=false
nuclei_cves=false
nuclei_dlogins=false
nuclei_panels=false
nuclei_exposures=false
nuclei_misc=false
nuclei_misconfig=false
nuclei_takeovers=false
nuclei_tech=false
nuclei_vuln=false
cors=false
nmap=false
crlf=false
or=false
output=false

while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in

   -domain)
         if [ -z "$2" ]; then
        echo "${red}Falta el argumento para -domain."
        flags
        exit 1
      fi

      domain="$2"
      shift 2
      ;;

    -recon)
      recon=true
      shift
      ;;
    -wayback)
      wayback=true
      shift
      ;;
    -dirsearch)
      dirsearch=true
      shift
      ;;
    -nuclei_cves)
      nuclei_cves=true
      shift
      ;;
    -nuclei_dlogins)
      nuclei_dlogins=true
      shift
      ;;
    -nuclei_panels)
      nuclei_panels=true
      shift
      ;;
    -nuclei_exposures)
      nuclei_exposures=true
      shift
      ;;
    -nuclei_misc)
      nuclei_misc=true
      shift
      ;;
    -nuclei_misconfig)
      nuclei_misconfig=true
      shift
      ;;
    -nuclei_takeovers)
      nuclei_takeovers=true
      shift
      ;;
    -nuclei_tech)
      nuclei_tech=true
      shift
      ;;
    -nuclei_vuln)
      nuclei_vuln=true
      shift
      ;;
    -cors)
      cors=true
      shift
      ;;
    -nmap)
      nmap=true
      shift
      ;;
    -crlf)
      crlf=true
      shift
      ;;
    -or)
      or=true
      shift
      ;;
    -output)
      output=true
      shift
      ;;
    *)
      echo "${red}Argumento invalido: $key"
      flags
      exit 1
      ;;
  esac
done

# Ejecutar tareas segun los flags
if [ "$recon" = true ]; then

  if [ -z "${domain}" ]; then
   domain=${subreport[1]}
   foldername=${subreport[2]}
   subd=${subreport[3]}
   report $domain $subdomain $foldername $subd; exit 1;
   fi
   clear
   logo
   if [ -d "$directory_data/$domain" ]
   then
     echo "${yellow}Este target fue escaneado previamente!."
     exit
   else
     mkdir $directory_data/$domain
fi

todate=$(date +"%Y-%m-%d")
path=$(pwd)
foldername=scan-$todate
  mkdir $directory_data/$domain/$foldername
  mkdir $directory_data/$domain/$foldername/nmap

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
mkdir $directory_data/$domain/subdomains
chaos -dL $domain -silent >> $directory_data/$domain/subdomains/subdomains.txt
subfinder -dL $domain -all -silent | anew $directory_data/$domain/subdomains/subdomains.txt
assetfinder --subs-only $domain | anew $directory_data/$domain/subdomains/subdomains.txt 

# Get alive subdomains 
notify "Running httpx"
mkdir $directory_data/$domain/httpx_info
cat $directory_data/$domain/subdomains/subdomains.txt | httpx -title -tech-detect -status-code -ip -p 80,443,8080,8081,9002,8443,81 >> $directory_data/$domain/httpx_info/httpx_full_info.txt

cat $directory_data/$domain/httpx_info/httpx_full_info.txt | awk '{print $1}' >> $directory_data/$domain/httpx_info/alive_subdomains.txt

# Take screenshots
notify "Taking screenshots"
mkdir $directory_data/$domain/screenshots
cat $directory_data/$domain/httpx_info/alive_subdomains.txt | aquatone -out $directory_data/$domain/screenshots

# Subdomains takeover 
notify "Check subdomains takeover with subzy"
mkdir $directory_data/$domain/vulns
subzy run --targets $directory_data/$domain/httpx_info/alive_subdomains.txt --hide_fails >> $directory_data/$domain/vulns/posible_takeover.txt

# XSS
notify "Running gau"
mkdir $directory_data/$domain/wayback_urls
gau --threads 16 --subs --blacklist png,jpg,gif,svg,woff,woff2 $domain >> $directory_data/$domain/wayback_urls/urls.txt
waybackurls $domain | anew $directory_data/$domain/wayback_urls/urls.txt
notify "Running katana"
katana -list $domain -d 5 -jc -silent | anew $directory_data/$domain/secrets/katana.txt
cat $directory_data/$domain/secrets/katana.txt >> $directory_data/$domain/wayback_urls/urls.txt
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
cat $directory_data/$domain/secrets/katana.txt $directory_data/$domain/wayback_urls/urls.txt | grep "\.js$" | httpx -mc 200 -silent >> $directory_data/$domain/secrets/js_files.txt
cat $directory_data/$domain/secrets/js_files.txt | while read url ; do
	python3 $tools_dir/secretfinder/SecretFinder.py -i $url -o $directory_data/$domain/secrets/results.html
done

zip -r results.zip $directory_data/$domain
notify "The scan has finished"
exit 0
