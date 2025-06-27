# sichere leitung

screenshot, setup:

![Screenshot](./ausgeschnitten.png)



# kurz und einfach
gcc -shared -fPIC -o auslagern.so auslagern.c \
    -O2 -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wl,-z,now,-z,relro,-z,noexecstack

___________________________________________________

python3 client.py
