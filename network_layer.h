#include "transport_layer.h"

int sizeIpPayload; //aux for size of IP payload

/*Build a IP header
* @ IHL: IP Header Length (* 4 bytes)
* @ protocol: number of IP protocol
* @ srcIP: IP source address. Example: "192.168.10.10"
* @ dstIP: IP destination address. Example: "192.168.10.20"
* @ payload: optional, set "" for 0
*/
unsigned char *  IPheader(int IHL, int protocol, char *srcIP, char *dstIP, unsigned char *payloadIP);


/*Build a IP packet
* @ srcMAC: source MAC address
* @ dstMAC: destination MAC address
* @ IP_header: correct IP header
*/
unsigned char * Build_packet_IP(unsigned char srcMAC[6], unsigned char dstMAC[6], unsigned char *IP_header);


/*Build a TCP/IP packet
* @ srcMAC: source MAC address
* @ dstMAC: destination MAC address
* @ IP_header: correct IP header
* @ TCP_header: correct TCP header
*/
unsigned char * Build_packet_IP_TCP(unsigned char srcMAC[6], unsigned char dstMAC[6], unsigned char *IP_header, unsigned char *TCP_header);