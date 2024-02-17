#!/bin/bash

function notify(){
  message=`echo -ne "##Kraken:\n *$1*" | sed 's/[^a-zA-Z 0-9*_]/\\\\&/g'`
  curl -s -X POST "https://api.telegram.org/bot$telegram_api_key/sendMessage" -d chat_id="$telegram_chat_id" -d text="$message" -d parse_mode="MarkdownV2" &> /dev/null
}

notify "Esto es una prueba"
