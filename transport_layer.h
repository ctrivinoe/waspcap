#include <stdlib.h>
#include <string.h>
int sizeTcpPayload; //aux for size of TCP payload

/*Build a TCP header
* @ sourcePort: number source port. Example: 80
* @ dstPort: number destination port. Example: 1343
* @ offset: total size of header (* 4 bytes)
* @ payload: optional, set "" for 0
*/
unsigned char * TCPheader(int sourcePort, int dstPort, int offset, unsigned char *payload);