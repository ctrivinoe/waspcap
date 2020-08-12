#include "transport_layer.h"


unsigned char * TCPheader(int sourcePort, int dstPort, int offset, unsigned char *payload){


    sizeTcpPayload = strlen(payload);

    int value = (offset*4) + sizeTcpPayload;
    unsigned char *packet = calloc(value, sizeof(unsigned char*));
    
    //Source port
    packet[0] = sourcePort >> 8;
    packet[1] = sourcePort & 0xFF;
    
    //Destination port
    packet[2] = dstPort >> 8;
    packet[3] = dstPort & 0xFF;

    //Sequence number 
    packet[4] = 0x00;
    packet[5] = 0x00;
    packet[6] = 0x00;
    packet[7] = 0x00;

    //Acknowledgment number
    packet[8] = 0x00;
    packet[9] = 0x00;
    packet[10] = 0x00; 
    packet[11] = 0x00; 

    //TCP Offset - Reserved - flags
    packet[12] = offset << 4;
    packet[13] = 0x01;

    //Window Size Value
    packet[14] = 0x00;
    packet[15] = 0x00;

    // Cheksum
    packet[16] = 0x00;
    packet[17] = 0x00;

    //Urgent Pointer
    packet[18] = 0x00;
    packet[19] = 0x00;

    int i;
    //options 0x00
    for (i = 20; i < (offset*4); i++)
    {
        packet[i] = 0x00;
    }

    if(sizeTcpPayload > 0)
    {
        int w;
        for (w = 0; w < sizeTcpPayload; w++)
        {
            packet[i] = payload[w];
            i++;
        }  
    }

    return packet;
}