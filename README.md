# Waspcap

En el siguiente documento encontrarás como utilizar la librería **Waspcap**, que permite la captura de paquetes de red valiéndose internamente de la famosa librería PCAP. También ofrece métodos para la creación de paquetes de red personalizados y la posibilidad de inyectarlos con fines de estudio para mejorar la seguridad en nuestras aplicaciones. La librería está escrita en C, es open-source y está preparada para correr en entornos Unix. 
## Pre-requisitos 📋
### Instalar PCAP
```
sudo apt-get install libpcap-dev
```
## Estructura de la librería

A continuación, se detallan los métodos, estructuras y variables presentes en los tres archivos de cabecera que conforman la librería: 
**transport_layer.h**: En esta cabecera se encuentra el método que simulará el nivel de transporte permitiéndonos construir cabeceras TCP.
**network_layer.h**: En esta cabecera se encuentran los métodos que simularán el nivel de red permitiéndonos construir cabeceras IP. También será la encargada de gestionar los métodos que acabarán construyendo los paquetes completos.
**control_management_pcap.h**: En esta cabecera se encuentran los métodos encargados de la captura de paquetes, gestión del enlace, datos de la red, inyecciones, control de datos, etc. haciendo uso de la librería PCAP. 

### transport_layer.h
### Variables globales
```
int sizeTcpPayload;
```
Dado que no hay manera de calcular el tamaño del payload únicamente con los datos ofrecidos por las cabeceras, se define el entero sizeTcpPayload para guardar de manera auxiliar el tamaño del payload pasado a la hora de construir la cabecera TCP.
### Métodos
#### TCPheader
```
unsigned char * TCPheader(int srcPort, int dstPort, int offset, unsigned char *payload);
```
El método TCPheader será el encargado de crear el array de bytes que será devuelto con formato de una cabecera TCP. Le pasaremos como parámetros srcPort y dstPort para indicar los puertos origen y destino. Con offset indicaremos el valor de dicho campo (el valor de offset será multiplicado por 4 para calcular el tamaño estándar de la cabecera). El array de payload es opcional y será para pasar una cadena como datos extra de la cabecera. Si no queremos esta carga de payload podemos pasar “” como parámetro. A la hora de calcular el tamaño de la cabecera, se tendrá en cuenta la longitud de este payload.
Ejemplo de llamada:
```
unsigned char *cabeceraTCP;

//cabecera TCP con puerto origen 34, destino 300, 5 en su campo Offset y el mensaje ABCDE como payload.
cabeceraTCP = TCPheader(34, 300, 5, "ABCDE");
…
//cabecera TCP con puerto origen 80, destino 100, 5 en su campo Offset y sin carga de payload.
cabeceraTCP = TCPheader(80, 100, 5, "");
```
### network_layer_h

### Variables globales
```
int sizeIpPayload;
```
Dado que no hay manera de calcular el tamaño del payload únicamente con los datos ofrecidos por las cabeceras, se define el entero sizeIpPayload para guardar de manera auxiliar el tamaño del payload pasado a la hora de construir la cabecera IP.

### Métodos

#### IPheader
```
unsigned char *  IPheader(int IHL, int protocol, char *srcIP, char *dstIP, unsigned char *payloadIP);
```
El método IPheader será el encargado de crear el array de bytes que será devuelto con formato de una cabecera IP. Con IHL indicaremos el valor de dicho campo (el valor de IHL será multiplicado por 4 para calcular el tamaño estándar de la cabecera). Mediante protocol estableceremos el número del protocolo que queramos para el paquete. También indicaremos mediante srcIP y dstIP las direcciones IP origen y destino, en formato decimal. El array de payload es opcional y será para pasar una cadena como datos extra de la cabecera. Si no queremos esta carga de payload podemos pasar “” como parámetro. A la hora de calcular el tamaño de la cabecera, se tendrá en cuenta la longitud de este payload.
Ejemplo de llamada:
```
unsigned char *cabeceraIP;

//cabecera IP con IHL 5 (tamaño estándar), protocolo 6 (cabecera IP para TCP), dirección origen 192.168.3.24 y o destino 8.8.8.10. Sin payload.
cabeceraIP = IPheader(5, 6, "192.168.3.24", "8.8.8.10","");
```
#### Build_packet_IP
```
unsigned char * Build_packet_IP(unsigned char srcMAC[6], unsigned char dstMAC[6], unsigned char *IP_header);
```
Este método será el encargado de construir un paquete IP completo. Para ello le pasaremos las direcciones MAC origen y destino (paquetes de 6 bytes) y la cabecera IP que habremos construido previamente. Internamente el método siempre supone que estamos utilizando IPv4. Este paquete estará listo para ser inyectado.
Ejemplo de llamada:
```
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

 unsigned char *cabeceraIP;
 unsigned char *paquete;

//construimos la cabecera IP
cabeceraIP = IPheader(5, 1, "192.168.3.24", "8.8.8.8", "");

//construimos el paquete con la cabecera IP
paquete = Build_packet_IP(mac1, mac2, cabeceraIP);
```
#### Build_packet_IP_TCP
```
unsigned char * Build_packet_IP_TCP(unsigned char srcMAC[6], unsigned char dstMAC[6], unsigned char *IP_header, unsigned char *TCP_header);
```
Este método será el encargado de construir un paquete IP/TCP completo. Para ello le pasaremos las direcciones MAC origen y destino (paquetes de 6 bytes) y las cabeceras IP TCP que habremos construido previamente. Internamente el método siempre supone que estamos utilizando IPv4. Este paquete estará listo para ser inyectado.
Ejemplo de llamada:
```
  unsigned char mac1[6];
  mac1[0] = 0x00;
  mac1[1] = 0x01;
  mac1[2] = 0x02;
  mac1[3] = 0x03;
  mac1[4] = 0x04;
  mac1[5] = 0x05;

  unsigned char mac2[6];
  mac2[0] = 0x10;
  mac2[1] = 0x11;
  mac2[2] = 0x12;
  mac2[3] = 0x13;
  mac2[4] = 0x14;
  mac2[5] = 0x15;
 unsigned char *cabeceraIP;
 unsigned char *cabeceraTCP;
 unsigned char *paquete;

//construimos la cabecera TCP con el mensaje ABCDE como payload
cabeceraTCP = TCPheader(80, 300, 5, "ABCDE");

//construimos la cabecera IP con protocolo 6: TCP
cabeceraIP = IPheader(5, 6, "192.168.3.24", "10.0.2.10","");

//construimos el paquete con ambas cabeceras
paquete = Build_packet_IP_TCP(mac1, mac2, cabeceraIP, cabeceraTCP);
```
### control_management_pcap.h

### Variables globales

```
int debug;
```
Entero que será comprobado para mostrar mensajes de debug durante la ejecución de los métodos. Con valor 1 estarán activados y con 0 desactivados.
control_handle
```
int control_handle;
```
Entero que indicará el estado del handle. Con valor 1 indicará que el handle está abierto (ya que el método que lo abre se habrá ejecutado correctamente). Con valor 0, indicará que no se ha abierto. Esta comprobación es necesaria ya que muchos métodos no pueden ejecutarse sin cumplirse esta condición.
control_devices_list
```
int control_devices_list;
```
Entero que indicará si se ha ejecutado el método GetAvailAdapters. Con valor 1 indicará que el método ya se ha ejecutad correctamente y con 0 que no. Esta comprobación es necesaria ya que algunos métodos no pueden ejecutarse sin cumplirse esta condición.

### Estructuras de datos internas

A continuación, se detallan las estructuras creadas para la librería.
#### assembled_Packet
```
typedef struct assembled_Packet {
    struct pcap_pkthdr header;
    const u_char *packet;
    char *name;
}apacket_t;
```

Struct que guardará la cabecera, cuerpo e identificados de los paquetes capturados en el buffer.

#### Interface
```
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
```
Struct que usaremos como parámetro en la mayoría de métodos. Guardará la información del dispositivo de red sobre el que estamos trabajando, como su nombre, dirección MAC, handle, estadísticas del mismo y el valor del buffer de captura de paquetes a través de otro thread (en caso de invocarlo).
Ejemplo de inicialización:
```
interface_t iface;
```
### Métodos

#### GetAvailAdapters
```
pcap_if_t GetAvailAdapters(); 
```
Método que devuelve en un struct tipo pcap_if_t (interno de PCAP) la lista de todos los dispositivos de red.
Ejemplo de llamada:
```
pcap_if_t interfaces;
interfaces = GetAvailAdapters();
```

#### PrintInterfaces
```
int PrintInterfaces(pcap_if_t *interfaces);
```
Método que lista por pantalla la lista de dispositivos disponibles.
La función retornará 0 si no hay errores. Si la lista de interfaces pasada no está inicializada, devolverá 1. 
Ejemplo de llamada:
```
PrintInterfaces(&interfaces);
```

#### SelectAdapter
```
int SelectAdapter(pcap_if_t *sDevice, interface_t *iface);
```
Método que lista por pantalla la lista de dispositivos disponibles para trabajar sobre ellos. Permite elegir uno de los listados colocándolo en el struct iface. Se consideran dispositivos disponibles aquellos que tienen valores de red y que además comiencen por la denominación eth, enp, wl o lo. Los parámetros pasados serán la lista de interfaces que se debe de haber cargado previamente y el struct interface.
La función retornará 0 si no hay errores. Si la lista de interfaces pasada no está inicializada, devolverá 1. 
Ejemplo de llamada:
```
SelectAdapter(&interfaces, &iface);
```

#### SetDeviceName
```
int setDeviceName(interface_t *iface, char *name);
```
Método que introduce el nombre pasado al campo device del struct interface.
La función retornará 0 si no hay errores 
Ejemplo de llamada:
```
setDeviceName(&iface, "enp0s3");
```

#### GetMACAdapter
```
int GetMACAdapter(interface_t *iface);
```
Carga la MAC del device con el nombre colocado en el struct interface.
La función retornará 0 si no hay errores. 
Ejemplo de llamada:
```
GetMACAdapter(&iface);
```

#### PrintMACAdapter
```
int PrintMACAdapter(interface_t *iface); 
```
Método que muestra por pantalla la dirección MAC guardada en el struct interface.
La función retornará 0 si no hay errores. 
Ejemplo de llamada:
```
PrintMACAdapter(&iface);
```

#### SetMACAdapter
```
int SetMACAdapter(interface_t *iface, unsigned char MACaddr[6]); 
```
Método que introduce el nombre pasado al campo MACaddr del struct interface.
La función retornará 0 si no hay errores. 


Ejemplo de llamada:
```
 unsigned char mac1[6];
  mac1[0] = 0x00;
  mac1[1] = 0x01;
  mac1[2] = 0x02;
  mac1[3] = 0x03;
  mac1[4] = 0x04;
  mac1[5] = 0x05;

SetMACAdapter(&iface, mac1);
```

#### OpenAdapter
```
int OpenAdapter(interface_t *iface); 
```
Método que abrirá el handle, descriptor. Es necesario para poder realizar la captura de los paquetes sobre el device previamente seleccionado. El dato pasado por parámetro será el struct interface.
La función retornará 0 si no hay errores, 1 en caso de error a la hora de abrirlo. 
Ejemplo de llamada:
```
OpenAdapter(iface.deviceName, &iface);
```

#### CloseAdapter
```
int CloseAdapter(interface_t *iface); 
```
Método que cerrará el handle. El dato pasado por parámetro será el struct interface.
La función retornará 0 si no hay errores. Retornará 1 si ocurre algún error. 
Ejemplo de llamada:
```
  CloseAdapter(&iface);
```

#### ReceiveFrame
```
int ReceiveFrame(interface_t *iface);
```
Método que capturará y mostrará un paquete de red tratado por el device cargado previamente. El dato pasado por parámetro será el struct interface.
La función retornará 0 si no hay errores. Retornará 1 si el handle está cerrado.

Ejemplo de llamada:
```
ReceiveFrame(&iface);
```

#### Receive_x_Frames
```
int Receive_x_Frames(interface_t *iface, int x);
```
Método que capturará X paquetes de red tratado por el device cargado previamente. Los datos pasados por parámetro serán el struct interface y el número de paquetes a capturar.
La función retornará 0 si no hay errores. Retornará 1 si el handle está cerrado.
Ejemplo de llamada:
```
Receive_x_Frames(&iface, 2)
```

#### GetStadistics
```
int GetStadistics(interface_t *iface); 
```
Método que cargará algunos datos sobre el handle: número de paquetes que pasaron por el filtro, número de paquetes que no han salido del Kernel y tipo de link-layer header. Este último será un valor que podremos consultar con detalle en https://www.tcpdump.org/linktypes.html. Los datos serán guardados dentro del struct interface y actualizados cada vez que se llame al método.
La función retornará 0 si no hay errores. Retornará 1 si el handle está cerrado.
Ejemplo de llamada:
```
GetStadistics(&iface);
```

#### FilterTcpdump
```
int FilterTcpdump(interface_t *iface, char const *filter_tcpdump);
```
Método que aplicará un filtro sobre el handle para la captura de mensajes. El filtro se indicará en formato TCPdump. 
La función retornará 0 si no hay errores. Retornará 1 si el handle está cerrado, 2 si no se ha podido obtener información sobre el dispositivo al que aplicar el filtro, 3 si el filtro es erróneo y 4 si ocurre algún problema interno a la hora de colocarlo.
Ejemplo de llamada:
```
FilterTcpdump(&iface, "port 80");
```
#### Dump2File
```
int Dump2File(interface_t *iface, int x, char *filename); 
```
Método que procesará X paquetes y volcará los aptos en un fichero que creará con el nombre que le pasemos como parámetro.
La función retornará 0 si no hay errores. Retornará 1 si se produce algún error de escritura y 2 en caso de fallar capturando.
Ejemplo de llamada:
```
Dump2File(&iface, 5, "capturados.pcap");
```

#### OpenDumpFile
```
int OpenDumpFile(char filename[80]);
```
Método que leerá todo el contenido volcado en un fichero de captura creado anteriormente con el nombre pasado por parámetro.
La función retornará 0 si no hay errores. Retornará 1 si se produce algún error a la hora de procesar el fichero.
Ejemplo de llamada:
```
OpenDumpFile("capturados.pcap");
```
#### Thread_capture
```
int Thread_capture(interface_t *iface, int x);
```
Método que lanzará un thread para capturar paquetes y enviarlos al buffer hasta llenarlo. Los datos pasados por parámetros serán el struct interface y el tamaño del buffer.
La función retornará 0 si no hay errores. Retornará 1 si se produce algún error a la hora de crear el hilo.
Ejemplo de llamada:
```
//Capturamos 5 paquetes en el buffer desde otro hilo
Thread_capture(&iface, 5);
```
#### Thread_receive
```
void Thread_receive(interface_t *iface);
```
Método interno que utilizará Thread_capture para inicializar la captura paralela. 
### ReadPacketsBuffer
```
int ReadPacketsBuffer(interface_t *iface);
```
Método que irá leyendo el buffer de paquetes. El hilo principal no podrá continuar hasta que el buffer haya sido llenado y leído al completo.
La función retornará 0 si no hay errores. Retornará 1 si el buffer no está inicializado.
Ejemplo de llamada:
```
ReadPacketsBuffer(&iface);
```
#### SendFrame
```
int SendFrame(interface_t *iface, unsigned char *p, int x);
```
Método que inyectará X veces el paquete bien formado que le pasemos por parámetro al dispositivo que estemos tratando. 
La función retornará 0 si no hay errores. Retornará 1 si el paquete es incorrecto y 2 si no se pudo realizar la inyección.
Ejemplo de llamada:
```
SendFrame(&iface, paquete, 2);
```
#### my_packet_handler
```
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
```
```
void packet_handler_thread(const struct pcap_pkthdr *header, const u_char *packet);
```
Método interno que gestionará el tratado del paquete capturado para mostrarlo por pantalla. packet_handler_thread será el método encargado de lo mismo pero dedicado a los paquetes del buffer en caso de estar capturando a través de otro thread.

#### ValidateOption
```
int ValidateOption(char num[], int max);
```
Método interno usado para validar que la opción seleccionada en el menú de SelectAdapter sea válida. En caso de no serla, gestiona el error y permite elegir de nuevo.

