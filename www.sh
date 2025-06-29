#!/bin/sh
DOMAIN="sichereleitung.duckdns.org"
TOKEN="204b1d6f-13e7-4c66-8ac7-ced57b54b22e"
while true; do
    CURRENT_IP=$(curl -s https://api.ipify.org)
    curl -s "https://www.duckdns.org/update?domains=$DOMAIN&token=$TOKEN&ip=$CURRENT_IP"
    sleep 300  # Warte 5 Minuten, bevor die IP erneut aktualisiert wird
done
