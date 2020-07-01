#include <stdio.h>
#include <stdlib.h>
#include "control_management_pcap.h"

/*To compile:

gcc main.c libcontrolpcap.a -lpcap -pthread -o main

*/

int main(int argc, char const *argv[])
{

  //struct info device
  interface_t iface;



  //struct list of interfaces
  pcap_if_t interfaces;

  int x = 100; //numero de paquetes a capturar

  printf("Activamos mensajes de error\n\n\n");
  debugmode(1);

  printf("Cargamos la lista de interfaces\n\n\n");
  interfaces = GetAvailAdapters();

  //Muestra por pantalla la lista de devices disponibles
  PrintInterfaces(&interfaces);


  //indica el nombre del device
  setDeviceName(&iface, "enp0s3");

  printf("El nombre del interfaz es: %s \n\n\n", iface.deviceName);
  
  //MAC del device
  GetMACAdapter(&iface);
  
  printf("Mostramos la MAC: \n\n");
    //MAC del device
  PrintMACAdapter(&iface);

  //abrimos el enlace
  printf("Abrimos el handle: \n\n\n");
  OpenAdapter(&iface);


  printf("Capturamos un paquete \n\n\n");
  ReceiveFrame(&iface);

  //obtenemos información del enlace
  GetStadistics(&iface);

  printf("Aplicamos filtro puerto 80 \n\n\n");
  FilterTcpdump(&iface, "port 80");

  printf("Capturamos X paquetes por el puerto 80\n\n\n"); 
  Receive_x_Frames(&iface, 2);

  //obtenemos información del enlace
  GetStadistics(&iface);

  //Procesamos 5 paquetes para un archivo .pcap
  Dump2File(&iface, 5, "capturados.pcap");

  //Capturamos 5 paquetes en el buffer desde otro hilo
  Thread_capture(&iface, 5);

  printf("\nPruebas de inyecciones: \n\n\n");

  unsigned char *cabeceraIP;
  unsigned char *cabeceraTCP;
  unsigned char *paquete;

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

  cabeceraIP = IPheader(5, 1, "192.168.3.24", "8.8.8.253", "A");
  paquete = Build_packet_IP(mac1, mac2, cabeceraIP);
  SendFrame(&iface, paquete, 5);

  cabeceraIP = IPheader(5, 1, "192.168.3.24", "8.8.8.253", "");
  paquete = Build_packet_IP(mac1, mac2, cabeceraIP);
  SendFrame(&iface, paquete, 5);

  cabeceraTCP = TCPheader(34, 300, 5, "ABCDE");
  cabeceraIP = IPheader(5, 6, "192.168.3.24", "8.8.8.253","");
  paquete = Build_packet_IP_TCP(mac1, mac2, cabeceraIP, cabeceraTCP);
  SendFrame(&iface, paquete, 4);

  cabeceraIP = IPheader(5, 1, "192.168.3.24", "8.8.8.253", "");
  paquete = Build_packet_IP(mac1, mac2, cabeceraIP);
  SendFrame(&iface, paquete, 5);

  cabeceraTCP = TCPheader(34, 300, 5, "dsfdsfdsAAAAAAAA"); 
  cabeceraIP = IPheader(5, 6, "192.148.3.24", "8.8.8.200","");
  paquete = Build_packet_IP_TCP(mac1, mac2, cabeceraIP, cabeceraTCP);
  SendFrame(&iface, paquete, 2);

  free(cabeceraTCP);
  free(cabeceraIP);
  free(paquete);

  printf("Leemos el buffer \n\n\n"); 
  ReadPacketsBuffer(&iface);

  printf("Leemos el archivo capturados.pcap \n"); 
  OpenDumpFile("capturados.pcap");

  printf("Cerramos el handle \n\n\n"); 

  CloseAdapter(&iface);

}

