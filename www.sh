#!/bin/sh
DOMAIN="meinserver.duckdns.org"
TOKEN="dein_duckdns_token"
while true; do
    CURRENT_IP=$(curl -s https://api.ipify.org)
    curl -s "https://www.duckdns.org/update?domains=$DOMAIN&token=$TOKEN&ip=$CURRENT_IP"
    sleep 300  # Warte 5 Minuten, bevor die IP erneut aktualisiert wird
done
