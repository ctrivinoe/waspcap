#include "transport_layer.h"

int sizeIpPayload; //aux for size of IP payload

/*Build a IP header
* @ IHL: IP Header Length (* 4 bytes)
* @ protocol: number of IP protocol
* @ source_IP: IP source address. Example: "192.168.10.10"
* @ destination_IP: IP destination address. Example: "192.168.10.20"
* @ payload: optional, set "" for 0
*/
unsigned char *  IPheader(int IHL, int protocol, char *source_IP, char *destination_IP, unsigned char *payloadIP);


/*Build a IP packet
* @ source_MAC: source MAC address
* @ destination_MAC: destination MAC address
* @ IP_header: correct IP header
*/
unsigned char * Build_packet_IP(unsigned char source_MAC[6], unsigned char destination_MAC[6], unsigned char *IP_header);


/*Build a TCP/IP packet
* @ source_MAC: source MAC address
* @ destination_MAC: destination MAC address
* @ IP_header: correct IP header
* @ TCP_header: correct TCP header
*/
unsigned char * Build_packet_IP_TCP(unsigned char source_MAC[6], unsigned char destination_MAC[6], unsigned char *IP_header, unsigned char *TCP_header);