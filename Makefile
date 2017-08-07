arp_spoof : arp_spoofing.c
	gcc -o arp_spoof -W -Wall -lpcap arp_spoofing.c

clean:
	rm arp_spoof
