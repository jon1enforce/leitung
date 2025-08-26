# sichere leitung

screenshot, setup:

![Screenshot](./ausgeschnitten.png)



# kurz und einfach
gcc -shared -fPIC -o auslagern.so auslagern.c \
    -O2 -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wl,-z,now,-z,relro,-z,noexecstack

___________________________________________________
linux/unix/bsd:    
python3 server.py  
python3 client.py  
___________________________________________________  
# TODO
1. "Call", die bidirektionale Audioübertragung testen und gegebenfalls korrigieren.
___________________________________________________  

# FINISHED  
1. (die aller-meisten)Sicherheits Funktionen sind fertig.  
2. User Interface  
3. "Setup" -> verbindet erfolgreich  
4. "Update" -> Telefonbuch update und Identitäts-session erfolgreich  
5. Mehrere clients threadsafe verwalten. Auf 2 ports 5060/5061  - braucht review, das meiste funktioniert.
