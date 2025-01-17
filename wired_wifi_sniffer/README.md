| Supported Targets  ESP32-S3 |
| --------------------------- |

# Wirless Sniffer 


## Overview

This is a wireless packet sniffer which is designed to pipe into wireshark directly via TCP protocol pcap format data  
for more infomation about wireshark named pipes go to [wireshark](https://wiki.wireshark.org/CaptureSetup/Pipes#tcp-socket).

It uses [TinyUSB](https://components.espressif.com/components/espressif/esp_tinyusb) software stack to emply NCM protocol which makes it look like it's network card windows.
Behind the scenes it setups to network interfaces, that one of them is TinyUSB which convertes ethernet packets over USB, and the other an internal iface which has an IP that windows can reach via the IP of USB NCM card.
the internal card acts as DHCP server and assigns an IP to the USB network card. 

For more information about pcap, please go to [wikipedia](https://en.wikipedia.org/wiki/Pcap).


## How to use

Plug the ESP32 S3 into you machine using the right conector, for windows 10 it will first show up as USB net and you will require to install NCM driver. 
[NCM-Driver](https://github.com/user-attachments/files/17932412/win10-native-ncm.pdf) W

Windows 11 may identify it automatically however it may idenify it as espressif Jtag driver, which you will need to reconfigure.
but it is important for it to be indentified as Espressief net card (under Network Adapters in device manager)

once the card is pluged , it will take a few seconds to be recognized by the machine

type `ipconfig` at your windows pormpt to examine all your network cards, one of them will show up like this: 
```bash

Ethernet adapter Ethernet: 

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : UsbNcm Host Device
   Physical Address. . . . . . . . . : 68-B6-B3-20-45-F3
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::9315:fbfd:3131:e146%84(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.5.2(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : יום שישי 17 ינואר 2025 13:24:00
   Lease Expires . . . . . . . . . . : יום שישי 24 ינואר 2025 12:04:00
   Default Gateway . . . . . . . . . : 192.168.5.1
   DHCP Server . . . . . . . . . . . : 192.168.5.1
   DHCPv6 IAID . . . . . . . . . . . : 1416148659
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-23-2E-5E-34-9C-5C-8E-BB-EB-06
   DNS Servers . . . . . . . . . . . : 192.168.5.1
   NetBIOS over Tcpip. . . . . . . . : Disabled
``` 
ping the ip listed in Default gatway and verify you're getting a reply.

```bash
C:\Users\User>ping 192.168.5.1

Pinging 192.168.5.1 with 32 bytes of data:
Reply from 192.168.5.1: bytes=32 time<1ms TTL=64
Reply from 192.168.5.1: bytes=32 time<1ms TTL=64
Reply from 192.168.5.1: bytes=32 time<1ms TTL=64
Reply from 192.168.5.1: bytes=32 time=1ms TTL=64

Ping statistics for 192.168.5.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```
then direct your browser to http://192.168.5.1
the browser will automaticaly update the sniffer with the currnet timestamp (and will continue to do so everytime you get back to it)

### Hardware Required

To run this with WiFi interface, you should have one ESP32 S3 dev board. 



### Build and Flash

```
idf.py -p PORT flash monitor
```
### Flash without build

download the [ESP32 Flash download tool](https://dl.espressif.com/public/flash_download_tool.zip)
open it in develop mode 

|offset  |	file					|
|--------|------					|
|0x0 		 |  bootloader.bin| 
|0x10000 |	WirlessSniffer_<version>.bin|
|0x8000  |	partition-table.bin| 
|0x210000| 	storage.bin|

select the 4 files above (and specify the offsets in the column next to it)
keep all the defaults and hit start , after flash has finished, reboot the device

See the [Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html) for full steps to configure and use ESP-IDF to build projects.

### `sniffer` Command Usage

> sniffer  [[-s <mac>] [-F <mgmt|data|ctrl|misc|mpdu|ampdu|fcsfail>]... [-c <channel>]
>   -F, --filter=<mgmt|data|ctrl|misc|mpdu|ampdu|fcsfail>  filter parameters
>   -c, --channel=<channel>  communication channel to use
>   -s, --source=<mac>  the mac address to filter

The `sniffer` command support some important options as follow:

* `-s`: Specify the MAC source address of the MAC
* `-c`: Specify the channel to sniff packet at `wlan` interface
* `-F`: Specify the filter condition at `wlan` interface
  * mgmt: Management packets
  * data: Data packets
  * ctrl: Control packets
  * misc: Other packets
  * mpdu: MPDU packets
  * ampdu: AMPDU packets

### `iface` Command usage 
> iface -i <ip>

the iface command allows you to change the IP the sniffer comes with:
* `-i`: specify the ip (for example 192.168.6.1) you'd like the sniffer to be addessable

this is beneficial in case you'd like to use several sniffers concurrently where each one would listen to a differnt channel 
and have wireshark connect to all of them.


#### Start Sniffer
type the following into your windows cli  
```bash
wireshark -i TCP@<ip> -k
```
to use wireshark with several sniffers:
```bash
wireshark -i TCP@<ip1> -i TCP@<ip2> -k
```
## Troubleshooting
