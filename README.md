# SympleLldpAgent
Simple LLDP agent for windows x64

https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol

Project redesigned from https://github.com/drxaos/lldp-beacon.

__Chassis ID:__ FQDN.

Hostname and Domain will be taken from GetNetworkParams (iphlpapi.h).

__Management address:__ resolved from hostname + DomainName.

__Port ID:__ the name of the interface if it exists and contains only US-ASCII([WIKI](https://en.wikipedia.org/wiki/ASCII)), otherwise MAC address.

Send lldp packets from all physical interfaces. Team interfaces are also processed, was tested on Windows with native, HPE and Brocade network adapters driver.

Download binary [releases](https://github.com/VictorPavlushin/SympleLldpAgent/releases)

# Running
```
SympleLldpAgent.exe 
```
LLDP packets are sent to all interfaces every 30 seconds

# Install as windows service
Copy SympleLldpAgent.exe to a new directory (e.g. C:\Program Files\SympleLldpAgent).

Run command:
To install
```
SympleLldpAgent.exe install
```
To remove service run command:
```
SympleLldpAgent.exe remove
``` 
