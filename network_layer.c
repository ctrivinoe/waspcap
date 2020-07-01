#include "network_layer.h"


unsigned char * IPheader(int IHL, int protocol, char *srcIP, char *dstIP, unsigned char *payloadIP){

    sizeIpPayload = strlen(payloadIP);
    char digits[4];
    int val = 0;
    int i = 0;
    int w = 0;

    int x = 0;
    x = (IHL * 4) + sizeIpPayload;

    unsigned char *packet = calloc(x, sizeof(unsigned char*));

    val = 64 + IHL; //IPv4 + IHL
    packet[0] = val;

    packet[1] = 0x00; // DSField ECN

    packet[2] = 0x00; // total length ....... calcular? Calculadora: Bytes total en wireshark - 13

    packet[3] = x; 
    
    packet[4] = 0x00; // identification
    packet[5] = 0x00; 

    packet[6] = 0x00; // Fragment offset
    packet[7] = 0x00; 

    packet[8] = 0x40; // TTL 

    packet[9] = protocol; // Protocol

    packet[10] = 0x00; // Header Cheksum 
    packet[11] = 0x00; 

    int k = 12;

    // Source Address
    for (i = 0; i <= strlen(srcIP) ; i++)
    {
      if(srcIP[i] == '.' || i == strlen(srcIP)){ 
          packet[k] = val;    
          digits[0] = ' ';digits[1] = ' ';digits[2] = ' '; //clear
          k++; w = 0;

      } else {
          digits[w] = srcIP[i];
          val = atoi(digits);
          w++;
      }
    }

    // Destination Address
    for (i = 0; i <= strlen(dstIP) ; i++)
    {
      if(dstIP[i] == '.' || i == strlen(dstIP)){ 
          packet[k] = val;    
          digits[0] = ' ';digits[1] = ' ';digits[2] = ' '; //clear
          k++; w = 0;

      } else {
          digits[w] = dstIP[i];
          val = atoi(digits);
          w++;
      }
    }

    if(sizeIpPayload > 0)
    {
        int w;
        int i = 20;
        for (w = 0; w < x; w++)
        {
            packet[i] = payloadIP[w];
            i++;
        }
    }
    
    return packet;
}


unsigned char * Build_packet_IP(unsigned char srcMAC[6], unsigned char dstMAC[6], unsigned char *IP_header){


    int x = 0;
    x = ((IP_header[0] & 0x0F)*4) + sizeIpPayload;

    int z = 14 + x;

    int i;
        


    unsigned char *packet = calloc(z, sizeof(unsigned char*));


    for (i = 0; i < 6; i++)
    {
        packet[i] = dstMAC[i];
    }
    for (i = 6; i < 12; i++)
    {
        packet[i] = srcMAC[i];
    }

    packet[12] = 0x08;
    i++;
    packet[13] = 0x00;
    i++;

    int w = 0;
    for (w = 0; w < x; w++)
    {
        packet[i] = IP_header[w];
        i++;
    } 

    return packet;


}


unsigned char * Build_packet_IP_TCP(unsigned char srcMAC[6], unsigned char dstMAC[6], unsigned char *IP_header, unsigned char *TCP_header){

    if(sizeIpPayload > 0)
        sizeIpPayload = 0;

    int x = 0;
    x = (IP_header[0] & 0x0F)*4;

    int y = 0;
    y = ((TCP_header[12] & 0xF0) >> 4)*4;

    int z = 14 + x + y + sizeTcpPayload;
    unsigned char *packet = calloc(z, sizeof(unsigned char*));

    int i;


    for (i = 0; i < 6; i++)
    {
        packet[i] = dstMAC[i];
    }
    for (i = 6; i < 12; i++)
    {
        packet[i] = srcMAC[i];
    }

    packet[12] = 0x08;
    i++;
    packet[13] = 0x00;
    i++;

    int w = 0;
    for (w = 0; w < x; w++)
    {
        packet[i] = IP_header[w];
        i++;
    } 

    packet[16] = 0x00;
    int val = x + y + sizeTcpPayload;
    packet[17] = val;
    for (w = 0; w < z; w++)
    {
        packet[i] = TCP_header[w];
        i++;
    } 

    return packet;
}


