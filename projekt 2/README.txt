*******************************
IPK PROJEKT č.2
autor: Vojtěch Jurka (xjurka08)
zadání ZETA
SNIFFER PAKETŮ
*******************************

Program zachytává datové pakety procházející přes zadané rozhraní.
Podporuje jen rozhraní ethernet, IP protokol verze 4 a TCP nebo UDP pakety.

překlad zdrojového kódu pomocí CMake:

make ipk-sniffer

Příklad spuštění programu

./ipk-sniffer -i eth0 -p23 --tcp -n 2

Seznam souborů:
1) ipk-sniffer.c
2) Makefile
3) README.txt
4) manual.pdf