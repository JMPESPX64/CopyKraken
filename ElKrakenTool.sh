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
notify=true
proxy_url="http://$PROXY_USERNAME:$PROXY_PASSWORD@45.88.101.118:5432"
########################################

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

##############################################################################Discovery START############################################################################
  notify "Listing subdomains using subfinder on $domain..."
  subfinder -all -silent -d "$domain" > $directory_data/$domain/$foldername/subdomain_ip.csv
  sleep 1
  cp $directory_data/$domain/$foldername/subdomain_ip.csv $directory_data/$domain/$foldername/$domain.txt
  notify "Probing for live hosts..."
  echo "$domain" >> $directory_data/$domain/$foldername/$domain.txt
  cat $directory_data/$domain/$foldername/$domain.txt | httpx >> $directory_data/$domain/$foldername/urllist.csv
  cp $directory_data/$domain/$foldername/$domain.txt $directory_data/$domain/$foldername/subdomain.csv
  notify "Total of $(wc -l < $directory_data/$domain/$foldername/urllist.csv | awk '{print $1}') live subdomains were found"
fi



##############################################################################wayback START############################################################################
if [ "$wayback" = true ]; then
#echo "${green}Starting to check available data in wayback machine"
notify "Staring to check available data in wayback machine"
waybackurls $value >> $directory_data/$domain/$foldername/wayback_tmp.txt
sleep 1
cat $directory_data/$domain/$foldername/wayback_tmp.txt | sort -u | uro > $directory_data/$domain/$foldername/wayback.txt
rm $directory_data/$domain/$foldername/wayback_tmp.txt
fi

##############################################################################Dirsearch START############################################################################
if [ "$dirsearch" = true ]; then
notify "Starting to check discovery with dirsearch"
dirsearch -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e $dirsearchExtensions -t 50 -exclude 403,401,404,400 -l $directory_data/$domain/$foldername/urllist.csv --deep-recursive -R 4 --crawl --full-url  --no-color --format=csv -o $directory_data/$domain/$foldername/dirsearch.csv
fi

##############################################################################OpenRedirect START############################################################################
if [ "$or" = true ]; then
notify "Starting to check Open Redirect"
cat $directory_data/$domain/$foldername/wayback.txt | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do; echo -e "$host" ;done >> $directory_data/$domain/$foldername/openredirect.csv 2>/dev/null
sleep 1
notify "Testing XSS"
gf xss $directory_data/$domain/$foldername/wayback.txt | kxss > posible_xss.txt

fi

##############################################################################nuclei START############################################################################
if [ "$nuclei_cves" = true ]; then
notify "Starting with nuclei"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t cves -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' > $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_vuln" = true ]; then
notify "Starting to check vulnerabilities"
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t vulnerabilities -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
notify "Vulnerability scanning is complete ->\n $(cat $directory_data/$domain/$foldername/nuclei.csv | grep -v ",info,")"
fi

if [ "$nuclei_dlogins" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t default-logins -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_panels" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t exposed-panels -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_exposures" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t exposures -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_misc" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t miscellaneous -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_misconfig" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t misconfiguration -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_takeovers" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t takeovers -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

if [ "$nuclei_tech" = true ]; then
nuclei -l $directory_data/$domain/$foldername/urllist.csv -no-color -t technologies -p "$proxy_url" | sed 's/ /,/g; s/\[//g; s/\]//g; s/(//g; s/)//g' >> $directory_data/$domain/$foldername/nuclei.csv
fi

##############################################################################CORS START############################################################################
if [ "$cors" = true ]; then
notify "Staring to check CORS vulnerabilities"
python3 $directory_tools/Corsy/corsy.py -i $directory_data/$domain/$foldername/urllist.csv -o $directory_data/$domain/$foldername/cors.json
notify "Cors scan has finished -> $(wc -l < $directory_data/$domain/$foldername/cors.json) results"
fi


##############################################################################Port Scan START############################################################################
if [ "$nmap" = true ]; then
notify "Staring to check Open Ports"
bash $directory_tools/customscripts/loop_nmap.sh $directory_data/$domain/$foldername/subdomain.csv
mv nmap_full_* $directory_data/$domain/$foldername/nmap/
fi

##############################################################################CRLF START############################################################################
if [ "$crlf" = true ]; then
notify "Starting to check CRLF"
crlfuzz -l $directory_data/$domain/$foldername/urllist.csv -o $directory_data/$domain/$foldername/crlfuzz_urllist.csv
crlfuzz -l $directory_data/$domain/$foldername/wayback.txt -o $directory_data/$domain/$foldername/crlfuzz_wayback.txt
cat $directory_data/$domain/$foldername/crlfuzz_urllist.csv > $directory_data/$domain/$foldername/crlfuzz.txt
cat $directory_data/$domain/$foldername/crlfuzz_wayback.txt >> $directory_data/$domain/$foldername/crlfuzz.txt
rm $directory_data/$domain/$foldername/crlfuzz_urllist.csv  $directory_data/$domain/$foldername/crlfuzz_wayback.txt
notify "CRLF recon finished -> $(wc -l < $directory_data/$domain/$foldername/crlfuzz_urllist.txt) results"
fi

##############################################################################Output START############################################################################
if [ "$output" = true ]; then
 scp -o  StrictHostKeyChecking=no -r ~/$domain $ssh_conection
notify "Finished recon on $(cat ~/tools/domains.txt) domains."
fi

