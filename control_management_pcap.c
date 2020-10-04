#include "control_management_pcap.h"


void debugmode(int option){
    debug = option;  

}


int GetMACAdapter(interface_t *iface){

    struct ifaddrs *ifaddr=NULL;
    struct ifaddrs *ifa = NULL;
    int i = 0;
    
    if (getifaddrs(&ifaddr) == -1)
    {
         perror("getifaddrs");
    }
    else
    {
         for ( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
         {
             if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) )
             {
                  struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;

                if(strcmp(ifa->ifa_name, iface->deviceName) == 0)
                {  
                    for (i=0; i <s->sll_halen; i++)
                    {
                      iface->MACaddr[i] =  s->sll_addr[i]; 
                    }
                }
             }
         }
         freeifaddrs(ifaddr);
    }
    if(debug==1)
        printf("\nMAC address getted succesfully. \n");
    return 0;
}


int PrintMACAdapter(interface_t *iface){

    int i = 0;

    printf("%s MAC address: ", iface->deviceName);

    for (i = 0; i < 5; i++)
    {
        printf("%02x : ", iface->MACaddr[i]);
    } 
    printf("%02x \n", iface->MACaddr[5]);
        
    return 0;
}


int SetMACAdapter(interface_t *iface, unsigned char newMACaddr[6]){

    int i = 0;

    for (i = 0; i < 6; i++)
    {
        iface->MACaddr[i] = newMACaddr[i];
    }

    if(debug == 1)
        printf("\nCorrectly setted new MAC address. \n");
    return 0;
}


int Dump2File(interface_t *iface, int x, char *filename){

    pcap_t *p; // Handle
    pcap_dumper_t *pd; // Dump file struct
    int pcount = 0; // Number of read packets 
    char prestr[80]; // prefix for errors

    if((pd=pcap_dump_open(iface->handle,filename)) == NULL)
    {
        fprintf(stderr,"Error opening file for writing: %s\n",pcap_geterr(p));
        return 1; 
    }

    while (pcount < x)
    {
        if((pcount=pcap_dispatch(iface->handle, x, &pcap_dump, (char*)pd)) < 0)
        {
            pcap_perror(iface->handle, prestr);
            return 2;
        }
    }

    if(debug == 1)
        printf("\nNumber of correctly processed packets: %d.\n",pcount);
    
    pcap_dump_close(pd);

    return 0;
}


int OpenDumpFile(char filename[80]){

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handleOffline;

    if(!(handleOffline = pcap_open_offline(filename, error_buffer))){
        fprintf(stderr,"Error: %s \n", error_buffer);
        return 1;
    }
 
    pcap_loop(handleOffline, 0, my_packet_handler, NULL); 

    pcap_close(handleOffline);

    return 0;
}


int SelectAdapter(pcap_if_t *sDevice, interface_t *iface){

    pcap_if_t *temp; // aux for loop
    int lookup_return_code;
    bpf_u_int32 ip_raw; // IP address as integer
    char *ip; 
    bpf_u_int32 subnet_mask_raw; // Subnet mask as integer
    char subnet_mask[13]; 
    struct in_addr address; // Used for both ip & subnet
    int i = 0;     
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *p; // for filter devices
    int ndevices = 0;
    int bool = 0;
    int bool2 = 0;
    int validator = 1;
    char ch[3];

    if(control_devices_list != 1)
    {
        if(debug == 1)
            printf("\nError, the list of network devices is not loaded.\n");
        return 1;
    }

    printf("\nAvaible interfaces: ");

    for(temp=sDevice;temp;temp=temp->next)
    {
        ndevices++;
    }

    int *vector;
    vector = (int *) malloc (sizeof(int) * ndevices);
    temp=sDevice; //restart temp

    for(temp=sDevice;temp;temp=temp->next)
    {
        // getting the current device information
        lookup_return_code = pcap_lookupnet(
            temp->name,
            &ip_raw,
            &subnet_mask_raw,
            error_buffer
        );

        p = temp->name;
        
        //interface filter: enp*, eth*, wl*, lo*
        if 
        (*p == 'e'){p++;if(*p == 'n'){p++;if(*p == 'p'){bool=1;}}} 
        else if 
        (*p == 'e'){p++;if(*p == 't'){p++;if(*p == 'h'){bool=1;}}}
        else if 
        (*p == 'w'){p++;if(*p == 'l'){bool=1;}}
        else if 
        (*p == 'l'){p++;if(*p == 'o'){bool=1;}}
        else {bool = 0;}

        //if the interface is one of the filtered and has useful values
        if (lookup_return_code != -1 && bool == 1){

                printf("\n\n[ %d ]:   %s \n",i,temp->name);

                // obtaining IP information and translation
                address.s_addr = ip_raw;
                strcpy(ip, inet_ntoa(address));
                    if (ip == NULL) {
                        perror("inet_ntoa: IP not assigned. \n\n"); 
                    }

                // obtaining mask information and translation
                address.s_addr = subnet_mask_raw;
                strcpy(subnet_mask, inet_ntoa(address));
                if (subnet_mask == NULL) {
                    perror("inet_ntoa: Mรกscara not assigned. \n\n"); 
                }
                
                printf("IP address: %s\n", ip);
                printf("Subnet mask: %s\n", subnet_mask); 
                vector[i] = 1;
        }
        i++;
        bool = 0;
    }
    int option;
    printf("\n\nSelect an interface: \n");

    while(bool2 == 0){
        
        scanf("%s", ch);

        option = ValidateOption(ch, ndevices);

        temp=sDevice; //restart temp
        //look for the selected device
        if(option < ndevices){
        for(i=0;i<=option;i++){
            
            if(i==option && vector[option] == 1){
                printf("\nThe selected interface is: [ %d ]:  %s \n\n",i,temp->name);
                
                strcpy(iface->deviceName, temp->name);
                bool2 == 1;
                return 0;
            } 
            temp=temp->next;
        }}
        printf("Wrong value, please select a valid value.\n");
    }

    return 2; //c error
}


int ValidateOption(char num[], int max){
    int val = 0;
    int number;

    while(val == 0){
    if(num[0] == '0'){
        if(num[1] != '\0'){
            printf("Wrong value, please select a valid value.รง\n");
            return 1; 
        } else {
 
            return 0;
        }       
    }

    val = atoi(num);  
    if(val != 0 && val > 0 && val < max){
        return val;
    } else {
        printf("Wrong value, please select a valid value.รง\n");
        
    }
       scanf("%s", num);
    } 
    return val; 
}


pcap_if_t GetAvailAdapters(){

    char error_buffer[PCAP_ERRBUF_SIZE]; 
    pcap_if_t *availAdapters;
    
    if(pcap_findalldevs(&availAdapters,error_buffer)==-1)
    {
        if(debug == 1)
            printf("\nError_buffer in pcap findall devs. \n");  
        exit(1);
    }

    if(debug == 1)
            printf("\nSuccessfully loaded list of network devices. \n"); 

    control_devices_list = 1;
    return *availAdapters;
}


int PrintInterfaces(pcap_if_t *interfaces){

    pcap_if_t *temp; // aux for loop
    int lookup_return_code;
    bpf_u_int32 ip_raw; // IP address as integer
    char *ip; 
    bpf_u_int32 subnet_mask_raw; // Subnet mask as integer 
    char subnet_mask[13]; 
    struct in_addr address; // Used for both ip & subnet 
    int i = 0;     
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *p; // for filter devices
    int bool = 0;

    if(control_devices_list != 1)
    {
        if(debug == 1)
            printf("\nError, the list of network devices is not loaded.\n");
        return 1;
    }

    printf("\nAvaible interfaces: ");
    for(temp=interfaces;temp;temp=temp->next)
    {

        // getting the current device information
        lookup_return_code = pcap_lookupnet(
            temp->name,
            &ip_raw,
            &subnet_mask_raw,
            error_buffer
        );

        p = temp->name;
        
        //interface filter
        if 
        (*p == 'e'){p++;if(*p == 'n'){p++;if(*p == 'p'){bool=1;}}} 
        else if 
        (*p == 'e'){p++;if(*p == 't'){p++;if(*p == 'h'){bool=1;}}}
        else if 
        (*p == 'w'){p++;if(*p == 'l'){bool=1;}}
        else if 
        (*p == 'l'){p++;if(*p == 'o'){bool=1;}}
        else {bool = 0;}
          
        //if the interface is one of the filtered and has useful values
        if (lookup_return_code != -1 && bool == 1)
        {
                printf("\n\n[ %d ]:   %s \n",i,temp->name);

                // obtaining IP information and translation
                address.s_addr = ip_raw;
                strcpy(ip, inet_ntoa(address));
                    if (ip == NULL) {
                        perror("inet_ntoa: IP not assigned. \n\n"); 
                    }

                // obtaining mask information and translation
                address.s_addr = subnet_mask_raw;
                strcpy(subnet_mask, inet_ntoa(address));
                if (subnet_mask == NULL) {
                    perror("inet_ntoa: Mรกscara not assigned. \n\n"); 
                }
                
                printf("IP address: %s\n", ip);
                printf("Subnet mask: %s\n", subnet_mask);          
        }
        i++;
        bool = 0;
    }
    printf("\n");
    return 0;
}


int setDeviceName(interface_t *iface, char *name){
    strcpy(iface->deviceName, name);
    if(debug == 1)
        printf("\nSet name correctly. \n");
    return 0;
}


int FilterTcpdump(interface_t *iface, char *filter_tcpdump){

    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;
    int snapshot_length = 1024;
    
    

    if(control_handle!=1)
    {
        if(debug == 1)
            printf("Filter Error: Closed handle");
        return 1;
    }


    //load data
    if (pcap_lookupnet(iface->deviceName, &ip, &subnet_mask, error_buffer) == -1)
    {
        if(debug == 1)
            printf("Filter Error: Could not get information for device: %s\n", iface->deviceName);
        
        ip = 0;
        subnet_mask = 0;
        return 2; 
    }
    if (pcap_compile(iface->handle, &filter, filter_tcpdump, 0, ip) == -1) 
    {
        if(debug == 1)
            printf("Filter Error: Bad filter - %s\n", pcap_geterr(iface->handle));
        return 3;
    }
    if (pcap_setfilter(iface->handle, &filter) == -1) 
    {
        if(debug == 1)
            printf("Filter Error: Error setting filter - %s\n", pcap_geterr(iface->handle));
        return 4;
    }

    if(debug == 1)
        printf("\nFilter applied correctly. \n");
    return 0;
}


int OpenAdapter(interface_t *iface){

    int snapshot_len = 1024;
    int promiscous = 1;
    int timeout = 1000;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int typeValue;
    
    iface->handle = pcap_open_live(iface->deviceName, snapshot_len, promiscous, timeout, error_buffer);
    
    if(iface->handle == 0)
    {
        if(debug == 1)
            printf("interface capture: failed \n");
        control_handle = 0;
        return 1;
    } else {
        if(debug == 1)
            printf("interface capture: success \n");
        iface->typeValue = -1;
        iface->packetsPassed = 0;
        iface->packetsNotPassed = 0;
        iface->buffsize = 0;
        control_handle = 1;
    }

    return 0;
}


int CloseAdapter(interface_t *iface){

    if(control_handle == 1)
    {
        pcap_close(iface->handle);
        if(debug == 1)
            printf("\nHandle closed succesfully.\n");    
    } else {
        if(debug == 1)
        printf("Failed closing the handle. \n");
        return 1;
    }

    return 0;
}


int GetStadistics(interface_t *iface){

    struct pcap_stat ps; //pcap stadistic struct
    int typeValue; //type for handle

    if(control_handle!=1)
    {
        if(debug == 1)
            printf("Error, handle closed. \n");
        return 1;
    }

    iface->typeValue = pcap_datalink(iface->handle);
    printf("Type link-layer header: ");
     switch(iface->typeValue)
        {
        case 0: printf("[0] INKTYPE_NULL DLT_NULL\n");
        break;
        case 1: printf("[1] LINKTYPE_ETHERNET   DLT_EN10MB\n");
        break;
        default:
                printf("[%d]\n", iface->typeValue);
        break;
        }

    //print the stadistics
    if(pcap_stats(iface->handle, &ps) != 0){
        fprintf(stderr,"Error getting stadistics: %s\n",pcap_geterr(iface->handle));
    exit(10);
    }

    iface->packetsPassed = ps.ps_recv;
    iface->packetsNotPassed = ps.ps_drop;
    printf("\nStadistics:\n");
    printf(" %d Number of packages that have passed the filter.\n",iface->packetsPassed);
    printf(" %d Number of packages that have NOT passed the filter\n",iface->packetsNotPassed);

    return 0;
}


int ReceiveFrame(interface_t *iface){

    if(control_handle!=1)
    {
        if(debug == 1)
            printf("Error, handle closed. \n");
        return 1;
    }

    pcap_loop(iface->handle, 1, my_packet_handler, NULL);

    return 0;

}


int Receive_x_Frames(interface_t *iface, int x){

    if(control_handle==1)
    {
        pcap_loop(iface->handle, x, my_packet_handler, NULL);
        return 0;
    } else {
        printf("Error, handle closed. \n");
        return 1;
    }
    
}


void Thread_receive(interface_t *iface){

    int i = 0;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    apacket_t pckt;

   for (i = 0; i < iface->buffsize; i++)
   {
        packet = pcap_next(iface->handle, &packet_header);

        if(packet == NULL)
        {
            printf("No packet found. \n");
            return;
        } else {

            pckt.packet = packet;
            pckt.header = packet_header;
            buffer[i] = pckt;
        }
    }
}


int Thread_capture(interface_t *iface, int x){

    pthread_t thread1;

    iface->buffsize = x;

    buffer = (apacket_t*) calloc(x, sizeof(apacket_t));

    //clean buffer
    int i = 0;
    for (i = 0; i < x; i++)
    {
        buffer[i].packet = NULL;
    }
    
    if(0 != pthread_create(&thread1,NULL, (void*)Thread_receive, iface)){
        if(debug == 1)
            printf("Error creating the thread\n");
        return 1;
    }

    return 0;
}


int ReadPacketsBuffer(interface_t *iface){

    int i = 0;

    if(iface->buffsize == 0){
        if(debug == 1)
            printf("Error, the buffer isn't initialized. \n");
        return 1;
    }
   
    for (i = 0; i < iface->buffsize; i = i)
    {
        if(buffer[i].packet != NULL)
        {
            printf ("\n\nReading the packet [%d] from the buffer... : \n\n", i);
            packet_handler_thread(&buffer[i].header, buffer[i].packet);
            i++;
          
        } else {
            usleep(500);
        }
        
    }
    free(buffer);
    return 0;
    
}


void packet_handler_thread(const struct pcap_pkthdr *header, const u_char *packet){

    
    int offset= 26; // 14MAC header+ 12IP
    printf("Packet received from: %d. %d. %d. %d\n",
    packet[offset],packet[offset+1],packet[offset+2],packet[offset+3]);
    if(header->caplen>= 34){
    printf("Destined to: %d. %d. %d. %d\n",packet[offset+4],packet[offset+5],packet[offset+6],packet[offset+7]);
    }
    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n", payload);
    printf("\n\n\n");
    return;


}


void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){


    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("Packet Type: IP\n");
    } else if ((ntohs(eth_header->ether_type) == ETHERTYPE_ARP)) {
        printf("Packet Type: ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Packet Type: Reverse ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Packet Type: Reverse ARP\n");
    }
    
    else {
        printf("Not an IP, ARP, Reverse ARP packet. Skipping...\n\n\n\n");
        return;
    }

    int offset= 26; // 14MAC header+ 12IP
    printf("Packet received from: %d. %d. %d. %d\n",
    packet[offset],packet[offset+1],packet[offset+2],packet[offset+3]);
    if(header->caplen>= 34){
    printf("Destined to: %d. %d. %d. %d\n",packet[offset+4],packet[offset+5],packet[offset+6],packet[offset+7]);
    }
    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n", payload);
    printf("\n\n\n");
    return;
}


int SendFrame(interface_t *iface, unsigned char *p, int x){

    if(sizeTcpPayload != 0 && sizeIpPayload != 0){
        if(debug==1)
            printf("incorrect headers.\n");
        return 1;
    }

    unsigned char sizeIP = (p[14]& 0x0F)*4;
    unsigned char sizeTCP = ((p[26 + sizeIP] & 0xF0) >> 4)*4;
    int packetSize = 14 + sizeIP + sizeTCP + sizeIpPayload + sizeTcpPayload;
    int i;

    for (i = 0; i < x; i++)
    {
      if(pcap_sendpacket(iface->handle, p, packetSize) == 0)
      {
          if(debug==1)
            printf("inject packet: success.\n");
      } else {
          if(debug==1)
            printf("inject packet: failed.\n");
            return 2;
      }
    }
    sizeIpPayload = 0;
    sizeTcpPayload = 0;


    return 0;
}


