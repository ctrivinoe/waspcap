#include "interface.h"
#include "control_management_pcap.h"



void print_image(FILE *fptr)
{
     char read_string[128];
    while(fgets(read_string,sizeof(read_string),fptr) != NULL)
        printf("%s",read_string);
}


void print_cover(){
       printf("\n");
    printf("\n");
    printf("\033[01;33m");

    char *filename = "image.txt";
        FILE *fptr = NULL;
    
        if((fptr = fopen(filename,"r")) == NULL)
        {
            fprintf(stderr,"error opening %s\n",filename);
            //return 1;
        }
    
        print_image(fptr);
    
        fclose(fptr);

    printf("\033[0m");

}

void print_menu(){
    printf("\n\nEnter a option: \n\n");
    printf("  [1]: Print Devices -> Print the list of available network devices. \n");
    printf("  [2]: Set Device -> Close the current interface and print the list of available network devices and let choose one. \n");
    printf("  [3]: Get MAC -> Get the MAC address of the current device. \n");
    printf("  [4]: FilterTCPdump 80 -> Set a filter for only capture on the port 80. \n");
    printf("  [5]: Capture X frames -> Capture a specified number of packets. \n");

    printf("  [6]: Thread Capture -> Capture a specified number of packets in another thread, saving them in a buffer. \n");
    printf("  [7]: Read PacketsBuffer -> Read all expected packets from the buffer \n");
    printf("  [8]: Get Stadistics -> Read all expected packets from the buffer \n");        

    
       
    printf("  [9]: Dump2File -> Capture a specified number of packets and dump them to a file.\n");
    printf(" [10]: OpenDumpFile -> Open a .pcap file for viewing. \n");
    printf("  [0]: Exit -> Finish the program and close the handle. \n");
}

