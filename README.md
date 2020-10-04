# Waspcap 🐝

**Waspcap** is a software project supported by the famous [PCAP](https://www.tcpdump.org/) interface, responsible for the development of such famous and powerful software as [Wireshark](), [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html) or [nmap](https://nmap.org/book/ndiff-man-web.html) among others.

The goal of **Waspcap** is didactic: to learn more about building network packets, protocol analysis, and other networking topics. It is also a project that supports the open-souce. It is released under a [GNU license](https://github.com/ctrivinoe/waspcap/blob/master/LICENSE).

Currently, **Waspcap** allows the analysis of our network interfaces, the capture of traffic, creation of custom packages and injection of them.

## Preview 👁️

![Gif Waspcap 1](https://media.giphy.com/media/5isVfw67Y5EzIwUDuv/giphy.gif)
![Gif Waspcap 2](https://media.giphy.com/media/8NdvLRJKU8t7xTOj7T/giphy.gif)
![Gif Waspcap 3](https://media.giphy.com/media/QwJQarQS0qBExWFGl2/giphy.gif)
![Capture wireshark](https://i.ibb.co/6gSqtDm/wireshak-capture.jpg)
<br>_A capture packet by Wireshark that we have injected with the payload ABCDE_

## Project history 📚

My idea for this project was born as a result of my internship at the University of Extremadura (studying software engineering), doing a small research project in the GITACA group under the supervision of the professor [David Cortés Polo](https://www.linkedin.com/in/david-cort%C3%A9s-polo-977326124/). I',m passionate about cybersecurity and networking, so the time spent on this project was very pleasant.

Despite spending years studying, I feel like I'm taking my first steps in the tech world now, feeling more and more involved in it. I want to contribute to the world of open-source software and access to media and information for all people, so it seems like a good idea to start contributing with what little I can!

In addition, when talking with other programmer friends, they often tell me that they see the issue of network packages confusing or complex, I think it is an interesting topic and we can all learn something (even if it is out of curiosity), and that it is not complicated (at first). I want to emphasize that I am not an expert on the subject, just another curious!

These were the main reasons that have led me to try to expand the project, initially as something personal (whether or not it has an impact), but with the hope that it may be useful or interesting to many people!

## Requirements 📋

⚠️ The program works correctly on [Ubuntu 18.04](https://releases.ubuntu.com/18.04/). Some distributions maybe are likely to have problems running it. It's a pending issue to improve.

### LibPCAP
```
sudo apt-get install libpcap-dev
```
## Structure ⚙️

* **transport_layer.h**: This header is in charge of simulating the transport layer. It has a method to construct the TCP header.
* **network_layer.h**: This header is in charge of simulating the network layer. It will also allow us to build IP headers and assemble all the parts to build the final network package.
* **control_management_pcap.h**: In this header are the methods in charge of packet capture, link management, network data, injections, data control, etc. making use of the PCAP library.
* **interface.h**: This header is in charge of printing the menu and some visual effects.
* **main.c**: Our Main will be in charge of launching the program and declaring the initial structures.

## Deployment 🚀🌐
You just have to run the makefile and execute ./waspcap!
```
sudo make
```

## Issues 🙋

Some questions that I want to propose (and also solve those that I can) are improvements to the code and memory management, more methods that improve and work with threads, manage the deployment in more distributions, creation and injection of specific packages (such as packages X), possibility of saving and loading custom packages and improve the menu to offer all current methods, among many others.

Also any correction of my English is welcome 😂

## Future of the project 🔮 

Aside from the posted and future issues, I plan to create a website for the project if it grows

## Tools and others 🛠️

* [libpcap](https://www.tcpdump.org/) 
* [Ubuntu 18.04](https://releases.ubuntu.com/18.04/)

* [Build our own TCP/IP packages from 0](https://dev.to/ctrivinoe/build-ur-tcp-ip-packet-1-4k60) - Dev.to


## Author & Contributors ✒️

* **Cristian Triviño Estévez** - [Personal Site](https://ctrivinoe.com)
* **Ahmed Elmayyah** - [Github](https://github.com/Satharus)
