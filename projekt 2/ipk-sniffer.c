#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>



void printData(const u_char* packet, int len)
{
	const u_char* ptr = packet;		//ukazatel do dat
	int line_len;			//delka aktualniho radku
	int remaining = len;	//delka zbyvajicich dat
	int offset = 0;


	while (remaining > 0)
	{
		//vypocitam delku aktualniho radku
		if (remaining >= 16)
		{
			line_len = 16;
		}
		else
		{
			line_len = remaining;
		}

		//vytisknu offset
		printf("0x%04x:  ", offset);

		//tisk hex bytu
		for (int i = 0; i < line_len; i++)
		{
			printf("%02x ", *ptr);
			ptr++;
			//za 8. bytem pridam mezeru
			if (i == 7)
			{
				printf(" ");
			}
		}

		//pokud mam mene nez 8 bytu, pridam mezeru taky pro zarovnani
		if (line_len < 8)
		{
			printf(" ");
		}

		//doplnim mezery do kratsiho radku pro zarovnani
		if (line_len < 16)
		{
			int gap = 16 - line_len;
			for (int i = 0; i < gap; i++)
			{
				printf("   ");
			}
		}

		//tisk mezery za hex cislami
		printf("  ");

		//pokud to jde, vytisknu i ascii reprezentaci bytu, pokud ne, vytisknu tecku
		ptr -= line_len; //posun ukazatele zpet

		for (int i = 0; i < line_len; i++)
		{
			if (isprint(*ptr))
			{
				printf("%c", *ptr);
			}
			else
			{
				printf(".");
			}
			ptr++;
		}
		//tisk newline za celym radkem
		printf("\n");


		offset += 16; //pridam k offsetu
		remaining -= line_len; //nova delka zbyvajicich dat
	}

}

void zpracujPaket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	struct ethhdr* ethernet = (struct ethhdr*)(packet);
	struct iphdr* ip = (struct iphdr*)(packet + 14); // velikost ethernet hlavicky je vzdy 14



	int size_ip = ip->ihl * 4; //header length je zapsan jako wordy, proto nasobime 4 abysme dostali bytes
	if (size_ip < 20)
	{
		printf("Spatna delka IP hlavicky.\n");
		return;
	}

	if (ip->version != 4)
	{
		printf("Nepodporovany typ ip hlavicky (IPv6).\n");
		return;
	}

	char time[50]; //promenna pro text s aktualnim casem

	//prevod aktualniho casu do stringu
	struct tm* t = localtime(&(header->ts.tv_sec));
	strftime(time, 50, "%X", t);

	//ziskani source a destination ip adresy z ip hlavicky
	struct in_addr saddr;
	saddr.s_addr = ip->saddr;
	char* srcip;
	srcip = inet_ntoa(saddr);

	char src_ip[20];
	strcpy(src_ip, srcip);


	struct in_addr daddr;
	daddr.s_addr = ip->daddr;
	char* dst_ip;
	dst_ip = inet_ntoa(daddr);

	//zjistim zda se jedna o TCP nebo UDP paket
	//nasleduje tisk na stdout s informacemi o paketu
	if (ip->protocol == IPPROTO_TCP) //je to tcp
	{
		struct tcphdr* tcp;
		tcp = (struct tcphdr*)(packet + 14 + size_ip);
		printf("%s.%d %s : %d > %s : %d\n\n", time, (int)header->ts.tv_usec, src_ip, ntohs(tcp->th_sport), dst_ip, ntohs(tcp->th_dport));

		int size_tcp = tcp->th_off * 4; //spocitam velikost tcp hlavicky
		if (size_tcp < 20)
		{
			printf("Spatna delka TCP hlavicky.\n");
			return;
		}
	}

	if (ip->protocol == IPPROTO_UDP) //je to udp
	{
		struct udphdr* udp;
		udp = (struct udphdr*)(packet + 14 + size_ip);
		printf("%s.%d %s : %d > %s : %d\n\n", time, (int)header->ts.tv_usec, src_ip, ntohs(udp->uh_sport), dst_ip, ntohs(udp->uh_dport));
		int size_udp = ntohs(udp->len) * 4; //spocitam velikost udp hlavicky
		if (size_udp < 20)
		{
			printf("Spatna delka UDP hlavicky.\n");
			return;
		}
	}

	//vypis dat 
	printData(packet, 14 + ntohs(ip->tot_len));

	//tisk newline za celym paketem
	printf("\n");


}


int main(int argc, char** argv)
{
	//flagy a promenne pro parsovani argumentu
	char* interface_arg = NULL;
	int port = -1;
	int tcpflag = 0;
	int udpflag = 0;
	int num = 1; //pocet paketu, ktere se maji zobrazit, implicitne 1

	//struktura pro longopts
	struct option longopts[2];
	longopts[0].name = "tcp";
	longopts[0].has_arg = no_argument;
	longopts[0].flag = &tcpflag;
	longopts[0].val = 1;
	longopts[1].name = "udp";
	longopts[1].has_arg = no_argument;
	longopts[1].flag = &udpflag;
	longopts[1].val = 1;

	int _longind; //promenna pro ukladani parametru funkce geopt_long
	char errbuff[PCAP_ERRBUF_SIZE]; //promenna pro pripadne ukladani error zprav od pcap funkci

	//parsovani argumentu
	int c;
	while ((c = getopt_long(argc, argv, "i:p:tun:", longopts, &_longind)) != -1)
	{
		switch (c)
		{
		case 'i':
			interface_arg = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 't':
			tcpflag = 1;
			break;
		case 'u':
			udpflag = 1;
			break;
		case 'n':
			num = atoi(optarg);
			break;
		case 0:
			break;
		default:
			fprintf(stderr, "ERROR: Nespravne zadane argumenty.\n");
			return 1;
		}
	}

	//pokud neni zadano rozhrani, program vypise seznam vsech aktivnich rozhrani a napovedu
	if (interface_arg == NULL)
	{
		printf("Packet sniffer.\nAutor: Vojtech Jurka(xjurka08)\n\n");
		printf("Pouziti:\n");
		printf("./ipk-sniffer -i [rozhrani] {-p [cislo]} {--tcp|-t} {--udp|-u} {-n [cislo]}\n\n");
		printf("-i [rozhrani]\n");
		printf("Nazev rozhrani, na kterem se bude poslouchat.\nNeni-li tento parametr uveden, vypise se seznam aktivnich rozhrani a tato napoveda.\n");
		printf("-p [cislo]\n");
		printf("Cislo portu, na kterem program hleda pakety.\nNeni-li tento parametr uveden, program hleda na vsech portech.\n");
		printf("-t nebo --tcp\n");
		printf("Pokud je zadan tento parametr, program hleda jen tcp pakety.\n");
		printf("-u nebo --udp\n");
		printf("Pokud je zadan tento parametr, program hleda jen upd pakety.\n");
		printf("Pokud neni zadan ani tcp nebo udp parametr, program hleda oba druhy paketu.\n");
		printf("-n [cislo]\n");
		printf("Tento parametr urcuje pocet paketu, ktere se maji zobrazit.\nPokud neni uvedeno, zobrazi se pouze 1 paket.\n\n");
		printf("SEZNAM AKTIVNICH ZARIZENI:\n");



		pcap_if_t* interfaces;

		if (pcap_findalldevs(&interfaces, errbuff) == PCAP_ERROR)
		{
			//pokud se nepodari najit aktivni rozhrani, vypisuju pcap error a koncim program
			fprintf(stderr, "ERROR:%s", errbuff);
			return 1;
		}

		while (interfaces != NULL) //prochazeni vytvorenym seznamem rozhrani
		{
			char description[100];
			if (interfaces->description == NULL) //pokud chybi popis rozhrani, doplnim ho
			{
				strcpy(description, "(no description)");
			}
			else
			{
				strcpy(description, interfaces->description);
			}
			printf("%s: %s\n", interfaces->name, description);

			interfaces = interfaces->next;
		}
		return 0; //po vypsani rozhrani ukoncuji program
	}

	//bylo zadano rozhrani argumentem, otevru ho
	pcap_t* int_handle; //vytvoreni promenne pro interface
	int_handle = pcap_open_live(interface_arg, BUFSIZ, 0, 200, errbuff);

	if (int_handle == NULL) //nepodarilo se otevrit
	{
		fprintf(stderr, "ERROR:%s", errbuff);
		return 1;
	}

	if (pcap_datalink(int_handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Zarizeni neni Ethernet.");
		exit(EXIT_FAILURE);
	}

	bpf_u_int32 mask; //sitova maska zarizeni
	bpf_u_int32 ip;   //ip zarizeni

	//zjisteni ip adresy a masky zarizeni
	if (pcap_lookupnet(interface_arg, &ip, &mask, errbuff) == -1)
	{
		fprintf(stderr, "ERROR: Nepodarilo se zjistit ip a masku. %s", errbuff);
		ip = 0;
		mask = 0;
	}

	struct bpf_program filtr; //promenna pro vysledny filtr
	char filtr_exp[30]; //vyraz pro vytvoreni filtru (vic nez 30 znaku nebudeme nikdy potrebovat)

	if (tcpflag == 1 && udpflag == 0) //byl zadan tcp flag, zobrazujeme pouze tcp pakety
	{
		if (port == -1)//nebyl zadan port, budeme hledat na vsech
		{
			sprintf(filtr_exp, "tcp");
		}
		else//je zadany port, filtrujeme podle nej
		{
			sprintf(filtr_exp, "tcp port %d", port);
		}
	}
	else if (tcpflag == 0 && udpflag == 1) //byl zadan udp flag, zobrazujeme pouze udp pakety
	{
		if (port == -1)//nebyl zadan port, budeme hledat na vsech
		{
			sprintf(filtr_exp, "udp");
		}
		else//je zadany port, filtrujeme podle nej
		{
			sprintf(filtr_exp, "udp port %d", port);
		}
	}
	else //neni zadan ani jeden nebo oba dva, zobrazujeme oba druhy zaroven
	{
		if (port == -1)//nebyl zadan port, budeme hledat na vsech
		{
			sprintf(filtr_exp, "tcp or udp");
		}
		else//je zadany port, filtrujeme podle nej
		{
			sprintf(filtr_exp, "(tcp or udp) and port %d", port);
		}
	}

	if (pcap_compile(int_handle, &filtr, filtr_exp, 0, ip) == -1)
	{
		fprintf(stderr, "Nepodarilo se zpracovat filtr.");
		return(1);
	}

	if (pcap_setfilter(int_handle, &filtr) == -1)
	{
		fprintf(stderr, "Nepodarilo se nastavit filtr.");
		return(1);
	}

	/*
	samotne ziskavani paketu - funkce ziska pocet paketu danych cislem num
	ziskanym z argumentu programu a pri kazdem paketu zavola funkci zpracujPaket
	*/

	pcap_loop(int_handle, num, zpracujPaket, NULL);



	pcap_close(int_handle);


	return 0;
}
