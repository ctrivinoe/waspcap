#include <stdio.h>
#include <stdlib.h>
#include "unistd.h"
#include "control_management_pcap.h"
#include "interface.h"

/*To compile and run:

gcc -c main.c transport_layer.c network_layer.c control_management_pcap.c

gcc -o demo1 main.o transport_layer.o network_layer.o control_management_pcap.o -lpcap -pthread

./demo1

*/

int main(int argc, char const *argv[])
{

  // *--- Declarations
  //struct info device
  interface_t iface;

  //struct list of interfaces
  pcap_if_t interfaces;

  // *--- Print cover:
  print_cover();
  sleep(1);
  
  // *--- Initial load:
  interfaces = GetAvailAdapters();
  printf("Please, select a interface for work with it: \n");
  SelectAdapter(&interfaces, &iface);
  //Get and print MAC
  GetMACAdapter(&iface);
  PrintMACAdapter(&iface);
  //Open the handle
  OpenAdapter(&iface);

  // *--- Menu:
    int nPackets;
    int nCharacters;
      int x=1;
    while (x != 0){
      print_menu();
    scanf("%d", &x);
    printf("\n");
    switch(x)
        {
        case 1:
            interfaces = GetAvailAdapters();
            PrintInterfaces(&interfaces);
        break;

        case 2:
            interfaces = GetAvailAdapters();
            SelectAdapter(&interfaces, &iface);
            OpenAdapter(&iface);
        break;

        case 3:
            GetMACAdapter(&iface);
            PrintMACAdapter(&iface);
        break;

        case 4:
            FilterTcpdump(&iface, "port 80");
        break;

        case 5:
            printf("\n");
            printf("Please, enter the number of packets for capture (0 for endless): ");
            scanf("%d", &nPackets);
            printf("\n\n Capturing... \n\n");
            Receive_x_Frames(&iface, nPackets);
        break;

        case 6:
            printf("\n");
            printf("Please, enter the number of packets for capture: (0 for endless)");
            scanf("%d", &nPackets);
            printf("\n\n Capturing... \n\n");
            Thread_capture(&iface, nPackets);
        break;

        case 7:
            ReadPacketsBuffer(&iface);
        break;

        case 8:
            GetStadistics(&iface);
        break;

        case 9:
            printf("\n");
            printf("Please, enter the number of packets for capture: ");
            scanf("%d", &nPackets);
            Dump2File(&iface,nPackets,"dumpFile.pcap");
        break;
        
        case 10:
            OpenDumpFile("dumpFile.pcap");
        break;

        case 0:        
        break;

        default:
        printf("Opción incorrecta.");
        break;
    }

    }
    printf("\nBye!\n\n");
  

  printf("\nInjections tests... \n\n\n");

  unsigned char *IPh;
  unsigned char *TCPh;
  unsigned char *packet;

  //Definimos una MAC origen
  unsigned char mac1[6];
  mac1[0] = 0x00;
  mac1[1] = 0x01;
  mac1[2] = 0x02;
  mac1[3] = 0x03;
  mac1[4] = 0x04;
  mac1[5] = 0x05;

  //Definimos una MAC destino
  unsigned char mac2[6];
  mac2[0] = 0x10;
  mac2[1] = 0x11;
  mac2[2] = 0x12;
  mac2[3] = 0x13;
  mac2[4] = 0x14;
  mac2[5] = 0x15;

  IPh = IPheader(5, 1, "192.168.3.24", "8.8.8.253", "A");
  packet = Build_packet_IP(mac1, mac2, IPh);
  SendFrame(&iface, packet, 5);

  IPh = IPheader(5, 1, "192.168.3.24", "8.8.8.253", "");
  packet = Build_packet_IP(mac1, mac2, IPh);
  SendFrame(&iface, packet, 5);

  TCPh = TCPheader(34, 300, 5, "ABCDE");
  IPh = IPheader(5, 6, "192.168.3.24", "8.8.8.253","");
  packet = Build_packet_IP_TCP(mac1, mac2, IPh, TCPh);
  SendFrame(&iface, packet, 4);

  IPh = IPheader(5, 1, "192.168.3.24", "8.8.8.253", "");
  packet = Build_packet_IP(mac1, mac2, IPh);
  SendFrame(&iface, packet, 5);

  TCPh = TCPheader(34, 300, 5, "EFGHI"); 
  IPh = IPheader(5, 6, "192.148.3.24", "8.8.8.200","");
  packet = Build_packet_IP_TCP(mac1, mac2, IPh, TCPh);
  SendFrame(&iface, packet, 2);

  free(TCPh);
  free(IPh);
  free(packet);

  printf("\nDone! \n\n\n");

  CloseAdapter(&iface);

}

