# IPK projekt č.1 -  HTTP resolver doménových jmen
**Autor: Vojtěch Jurka (xjurka08)**

 1. Popis funkce skriptu
Skript v jazyce Python spustí server, který po navázání spojení s klientem přijme HTTP request a začne ho zpracovávat. Podle prvního slova ve zprávě od klienta pozná, zda se jedná o požadavek GET nebo POST, v jiném případě vrátí HTTP hlavičku s chybou 405. 
Potom podle typu požadavku zavolá funkci getFunction(), respektive postFunction, předá jí data požadavku od klienta a daná funkce ho zpracuje. Poté funkce vrací hotovou formátovanou HTTP hlavičku i se zprávou, která se odesílá zpět klientovi. Server po odeslání zprávy opět čeká na další zprávu od klienta.

 2. Pomocné funkce
Funkce na zpracování samotných požadavků fungují hlavně na bázi práce se řetězcovými literály, jejich rozdělování pomocí vestavěné funkce split() do listů. Následuje práce s listy naplněnými řetězci. Funkce postupně analyzují zprávu od klienta a po kontrole jejího formátu předávají funkcím gethostbyname() a gethostbyaddr() už samotné IP adresy, nebo doménová jména. Tyto funkce je přeloží a vrací informace v podobě řetezců zpět. Ty jsou následně opět zpracovávány, osazeny HTTP hlavičkou a vraceny nazpět volajícímu samotné pomocné funkce.

3. Testování
Skript jsem testoval pomocí programu curl s IP adresou serveru nastavenou jako localhost. Po zasílání zprávě serveru  skript úspěšně odpovídal a curl zobrazoval výsledné přeložené IP adresy/doménová jména.

 4. Spouštění skriptu
Skript má vytvořený pro spouštění Makefile. Spouští se příkazem "make run PORT=1234", kde "1234" je číslo portu, na kterém se spustí server.