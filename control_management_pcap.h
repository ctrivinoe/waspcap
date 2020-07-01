#include <stdio.h>
#include <string.h> 
#include <pcap.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ifaddrs.h> 
#include <netpacket/packet.h> 
#include <stdlib.h>
#include <pthread.h> 
#include <unistd.h> 
#include "network_layer.h"
#include "transport_layer.h"


int debug;
int control_handle; //1 = open, 0 = closed
int control_devices_list; //1 = charged, 0 = no

typedef struct assembled_Packet {
    struct pcap_pkthdr header;
    const u_char *packet;
    char *name;
}apacket_t;

apacket_t *buffer; //Packets's buffer

typedef struct interface {
    char deviceName[10];
    unsigned char MACaddr[6];
    pcap_t *handle;

    //Handle's stadistics:
    int typeValue;
    u_int packetsPassed;
    u_int packetsNotPassed;

    //size buffer
    int buffsize;
}interface_t;


//Return the list of available network devices
pcap_if_t GetAvailAdapters(); 

/*Print the list of available network devices and let choose one. Set the selected device on iface.
* @ sDevice: list of devices
* @ iface: interface struct
* Return 0 when there is no error
* List of errors:
* 1: the list of network devices is not loaded.
* 2: c error
*/
int SelectAdapter(pcap_if_t *sDevice, interface_t *iface);


/*Create a dump file and capture X packets
* @ iface: interface struct 
* @ x: number of packets
* @ filename: name of the filename. You must use .pcap format!
* Return 0 when there is no error
* List of errors:
* 1: Error opening file for writing
* 2: Capture failed
*/
int Dump2File(interface_t *iface, int x, char *filename); 

/*Open and read a dumpfile
* @ filename: name of the filename.
* Return 0 when there is no error
* List of errors:
* 1: Error opening offline handle
*/
int OpenDumpFile(char filename[80]);


/*Set device name on iface
* @ iface: interface struct 
* @ name: device name
* Return 0 when there is no error
*/
int setDeviceName(interface_t *iface, char *name); //return 0 //ADAPTER


/*Set a filter in format TCPdump 
* @ iface: interface struct 
* @ filter_tcpdump: filter
* Return 0 when there is no error
* List of errors:
* 1: Error: Closed handle
* 2: Error: Could not get information for device
* 3: Error: Bad filter
* 4: Error setting filter
*/
int FilterTcpdump(interface_t *iface, char const *filter_tcpdump);

/*Get the MAC address from the loaded device and set in iface
* @ iface: interface struct 
* Return 0 when there is no error
*/
int GetMACAdapter(interface_t *iface);

/*Print the MAC address from iface
* @ iface: interface struct 
* Return 0 when there is no error
*/
int PrintMACAdapter(interface_t *iface); 

/*Set the new MAC address in iface
* @ iface: interface struct 
* @ MACaddr: new MAC address
* Return 0 when there is no error
*/
int SetMACAdapter(interface_t *iface, unsigned char MACaddr[6]);  

/*Print the list of available network devices.
* @ interfaces: list of devices
* Return 0 when there is no error
* List of errors:
* 1: the list of network devices is not loaded.
* 2: c error
*/
int PrintInterfaces(pcap_if_t *interfaces);

/*Open the handle
* @ device: device name
* @ iface: interface struct 
* Return 0 when there is no error
* List of errors:
* 1: interface capture: failed
*/
int OpenAdapter(interface_t *iface); 

/*Close the handle
* @ iface: interface struct 
* Return 0 when there is no error
* List of errors:
* 1: Failed closing the handle.
*/
int CloseAdapter(interface_t *iface); 


/*Capture a packet
* @ iface: interface struct 
* Return 0 when there is no error
* List of errors:
* 1: Error, handle closed.
*/
int ReceiveFrame(interface_t *iface);

/*Capture X packet
* @ iface: interface struct 
* @ x: number of packets. If x <= 0, unlimited capture 
* Return 0 when there is no error
* List of errors:
* 1: Error, handle closed.
*/
int Receive_x_Frames(interface_t *iface, int x);


/*Print handle's stadistics: Type link-layer header an number of packets that have and not passed the filtre
* @ iface: interface struct 
* Return 0 when there is no error
* List of errors:
* 1: Error, handle closed.
*/
int GetStadistics(interface_t *iface); 

/*Read all expected packets from the buffer
* @ iface: interface struct 
* Return 0 when there is no error
* List of errors:
* 1: Error, the buffer isn't initialized.
*/
int ReadPacketsBuffer(interface_t *iface);

/*Capture and send the packets to buffer
* @ iface: interface struct 
*/
void Thread_receive(interface_t *iface);

/*initialize the method Thread_receive in another thread
* @ iface: interface struct 
* @ x: number of packets to capture
* Return 0 when there is no error
* List of errors:
* 1: Error creating the thread
*/
int Thread_capture(interface_t *iface, int x);

/*initialize the method Thread_receive in another thread
* @ iface: interface struct 
* @ p: package to inject
* @ x: number of injections
* Return 0 when there is no error
* List of errors:
* 1: Incorrect headers
* 2: Inject packet: failed
*/
int SendFrame(interface_t *iface, unsigned char *p, int x);


//manage the capture methods of PCAP
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
//manage the capture methods of PCAP
void packet_handler_thread(const struct pcap_pkthdr *header, const u_char *packet);


int ValidateOption(char num[], int max); 

/*Activates debug messages
* @ option: 1: ON \ 0: OFF
*/
void debugmode(int option); 




