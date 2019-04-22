#include "Header.h"

HINSTANCE dllHandle;
dll_pcap_open pcap_open;
dll_pcap_close pcap_close;
dll_pcap_sendpacket pcap_sendpacket;
dll_pcap_geterr pcap_geterr;

int run_loop = 1;



void lldp() {
	dbg << "Job run";
	FIXED_INFO *pFixedInfo;
	ULONG ulOutBufLen;

	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	unsigned int i, j;

	MIB_IF_TABLE2 *pIfTable;
	MIB_IF_ROW2 *pIfRow;

	string dnsname;

	pFixedInfo = (FIXED_INFO*)MALLOC(sizeof(FIXED_INFO));
	pIfTable = (MIB_IF_TABLE2*)MALLOC(sizeof(MIB_IF_TABLE2));

	if (pFixedInfo == NULL) {
		dbg << "Error allocating memory needed to call GetNetworkParams";
		goto FreeMemory;
	}
	ulOutBufLen = sizeof(FIXED_INFO);

	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)MALLOC(ulOutBufLen);
		if (pFixedInfo == NULL) {
			dbg << "Error allocating memory needed to call GetNetworkParams\n";
			goto FreeMemory;
		}
	}

	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR) {
		dbg << "Error call GetNetworkParams";
		goto FreeMemory;
	}
	dnsname = pFixedInfo->HostName + string(".") + pFixedInfo->DomainName;
	transform(dnsname.begin(), dnsname.end(), dnsname.begin(), ::tolower);
	dbg << "Hostname: " << dnsname;

	struct hostent* Host;
	struct in_addr addr;
	WSADATA wsaData;
	int iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		dbg << "WSAStartup failed: " << iResult;
		goto FreeMemory;
	}
	Host = gethostbyname(dnsname.c_str());
	i = 0;
	if (Host->h_addrtype == AF_INET && Host->h_addr_list[0] != 0)
	{
		addr.s_addr = *(u_long*)Host->h_addr_list[0];
	}
    dbg << "IP Address :" << inet_ntoa(addr);

	// Allocate memory for our pointers.
	if (pIfTable == NULL) {
		dbg << "Error allocating memory needed to call GetIfTable2";
		goto FreeMemory;
	}

	// Make an initial call to GetIfTable2 to get the
	// necessary size into dwSize
	dwSize = sizeof(MIB_IF_TABLE2);
	if (GetIfTable2(&pIfTable) == ERROR_NOT_ENOUGH_MEMORY) {
		FREE(pIfTable);
		pIfTable = (MIB_IF_TABLE2*)MALLOC(dwSize);
		if (pIfTable == NULL) {
		dbg << "Error allocating memory needed to call GetIfTable2";
		goto FreeMemory;
		}
	}
	if ((dwRetVal = GetIfTable2(&pIfTable)) == NO_ERROR) {
		for (i = 0; i < pIfTable->NumEntries; i++) {
			pIfRow = (MIB_IF_ROW2*)& pIfTable->Table[i];
			if (pIfRow->PhysicalMediumType == NdisPhysicalMedium802_3 
				&& pIfRow->MediaType == NdisMedium802_3
				&& pIfRow->PhysicalAddressLength
				&& !pIfRow->InterfaceAndOperStatusFlags.FilterInterface
				&& pIfRow->InterfaceAndOperStatusFlags.HardwareInterface) {

				OLECHAR* guid;
				if (StringFromCLSID(pIfRow->InterfaceGuid, &guid) != S_OK) {
					dbg << "Failed get GUID to adapter index: " << pIfRow->InterfaceIndex;
					continue;
			    }
				string rpcap = "rpcap://\\Device\\NPF_";
				USES_CONVERSION;
				rpcap.append(W2A(guid));
				FREE(guid);
				
				pcap_t* fp;
				char errbuf[PCAP_ERRBUF_SIZE];
				dbg << "Open pcap: " << rpcap;
				if ((fp = pcap_open(rpcap.c_str(),
					100,                // portion of the packet to capture (only the first 100 bytes)
					PCAP_OPENFLAG_NOCAPTURE_RPCAP,
					1000,               // read timeout
					NULL,               // authentication on the remote machine
					errbuf              // error buffer
				)) == NULL) {
					dbg << "Unable to open the adapter. " << rpcap.c_str() << " is not supported by WinPcap";
					continue;
				}
				
				vector<u_char> packet;
				// LLDP_MULTICAST
				packet.push_back(0x01);
				packet.push_back(0x80);
				packet.push_back(0xc2);
				packet.push_back(0x00);
				packet.push_back(0x00);
				packet.push_back(0x0e);
				
				// SRC MAC
				string strmak;
				for (j = 0; j < (int)pIfRow->PhysicalAddressLength; j++) {
					packet.push_back((u_char)pIfRow->PhysicalAddress[j]);
				}
				dbg << "Building packet: SRC MAC: " << hex
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[0] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[1] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[2] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[3] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[4] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[5]
					<< dec << setw(1);

				// ETHERNET_TYPE_LLDP
				packet.push_back(0x88);
				packet.push_back(0xcc);

				dbg << "Building packet: CHASSIS ID: " << dnsname;
				packet.push_back(0x02); // chassis id
				packet.push_back((u_char)(dnsname.length() + 1));
				packet.push_back(0x07); // locally assigned
				for (int j = 0; j < dnsname.length(); ++j) {
					packet.push_back((u_char)dnsname.c_str()[j]);
				}

				// PORT SUBTYPE
				wstring TifAlias(pIfRow->Alias);
				char alias[sizeof(pIfRow->Alias)];
				sprintf(alias, "%ws", pIfRow->Alias);
				//string ifAlias(TifAlias.begin(), TifAlias.end());
				bool ansi = TRUE;
				for (j = 0; j < TifAlias.size(); j++) {
					if ((u_char)alias[j] > 127)
					{
						ansi = FALSE;
						break;
					}
				}
				packet.push_back(0x04); // port id
				if (TifAlias.size() && ansi) {
					packet.push_back(1+ TifAlias.size()); // size: 1 + sizeof(ifName)
					packet.push_back(0x01); // type = ifAlias (IETF RFC 2863)
					dbg << "Building packet: PORT ID: " << alias;
					for (int j = 0; j < TifAlias.size(); j++) {
						packet.push_back((u_char)alias[j]);
					}
				} else {
					dbg << "Building packet: PORT ID: " << hex
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[0] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[1] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[2] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[3] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[4] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[5]
						<< dec << setw(1);

					packet.push_back(0x07); // size 1+6
					packet.push_back(0x03); // type = mac address
					for (int j = 0; j < 6; ++j) {
						packet.push_back(pIfRow->PhysicalAddress[j]);
					}
				}

				// TTL
				packet.push_back(0x06); // TTL
				packet.push_back(0x02); // size 1+1
				packet.push_back(0x00); // 120 sec
				packet.push_back(0x78);

				// Port description
				wstring TDescription(pIfRow->Description);
				string Description(TDescription.begin(), TDescription.end());
				dbg << "Building packet: Port Desc: " << Description;
				packet.push_back(0x08); // Port Description
				packet.push_back(Description.size()); // Description length
				for (int j = 0; j < Description.size(); ++j) {
					packet.push_back((u_char)Description[j]);
				}

				// System name
				dbg << "Building packet: Sys Name: " << dnsname;
				packet.push_back(0x0a); // System name
				packet.push_back((u_char)dnsname.length()); // Name length
				for (int j = 0; j < dnsname.length(); ++j) {
					packet.push_back(dnsname[j]);
				}

				// System description
				string osname("Windows");
				dbg << "Building packet: Sys Desc: " << osname;
				packet.push_back(0x0c); // System desc
				packet.push_back((u_char)osname.length()); // Name length
				for (int j = 0; j < osname.length(); ++j) {
					packet.push_back((u_char)osname[j]);
				}

				// Caps
				packet.push_back(0x0e); // Sys caps
				packet.push_back(0x04); // size 2+2
				packet.push_back(0x00); //
				packet.push_back(0x80); // station only
				packet.push_back(0x00); //
				packet.push_back(0x80); // station only

				// Management address
                dbg << "Building packet: Management address: " << inet_ntoa(addr);
				packet.push_back(0x10); // Management addr
				packet.push_back(0x0c); // size 12
				packet.push_back(0x05); // addr len 1+4
				packet.push_back(0x01); // addr subtype: ipv4
				packet.push_back((u_char)addr.S_un.S_un_b.s_b1); // ip
				packet.push_back((u_char)addr.S_un.S_un_b.s_b2); // ip
				packet.push_back((u_char)addr.S_un.S_un_b.s_b3); // ip
				packet.push_back((u_char)addr.S_un.S_un_b.s_b4); // ip
				dbg << "Building packet: Management address: if subtype - ifIndex: " << pIfRow->InterfaceIndex;
				packet.push_back(0x02); // if subtype: ifIndex
				BYTE* pbyte = (BYTE*) & (pIfRow->InterfaceIndex);
				packet.push_back(pbyte[3]); // id
				packet.push_back(pbyte[2]); // id
				packet.push_back(pbyte[1]); // id
				packet.push_back(pbyte[0]); // id
				packet.push_back(0x00); // oid len 0

				// IEEE 802.3 - MAC/PHY Configuration/Status
				packet.push_back(0xfe); //
				packet.push_back(0x09); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0x0f); //
				packet.push_back(0x01); //
				packet.push_back(0x02); //
				packet.push_back(0x80); //
				packet.push_back(0x00); //
				packet.push_back(0x00); //
				packet.push_back(0x1e); //

				// IEEE 802.3 - Maximum Frame Size
				packet.push_back(0xfe); //
				packet.push_back(0x06); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0x0f); //
				packet.push_back(0x04); //
				packet.push_back(0x05); //
				packet.push_back(0xee); //

				// TIA TR-41 Committee - Media Capabilities
				packet.push_back(0xfe); //
				packet.push_back(0x07); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0xbb); //
				packet.push_back(0x01); //
				packet.push_back(0x01); //
				packet.push_back(0xee); //
				packet.push_back(0x03); //

				// TIA TR-41 Committee - Network Policy
				packet.push_back(0xfe); //
				packet.push_back(0x08); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0xbb); //
				packet.push_back(0x02); //
				packet.push_back(0x06); //
				packet.push_back(0x80); //
				packet.push_back(0x00); //
				packet.push_back(0x00); //

				// TIA TR-41 Committee - Network Policy
				packet.push_back(0xfe); //
				packet.push_back(0x08); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0xbb); //
				packet.push_back(0x02); //
				packet.push_back(0x07); //
				packet.push_back(0x80); //
				packet.push_back(0x00); //
				packet.push_back(0x00); //

				// End of LLDPDU
				packet.push_back(0x00); // type
				packet.push_back(0x00); // len 0

				// Send down the packet
				dbg << "Sending packet (size: " << packet.size() << ")";
				if (pcap_sendpacket(fp, packet.data(), packet.size()) != 0) {
					fprintf(stderr, "\nError sending the packet: \n");
					fprintf(stderr, pcap_geterr(fp));
					fprintf(stderr, "\n");
				}

				dbg << "Closing pcap";
				pcap_close(fp);
				packet.clear();
			}
		}
	}
FreeMemory:
	if (pFixedInfo)
		FREE(pFixedInfo);
	if (pIfTable)
		FREE(pIfTable);
}

void wait(basic_ostream<char>* progress, int sec) {
	*progress << "Sleeping " << sec << "sec";
	for (int i = 0; i < sec; ++i) {
		if (!run_loop) {
			dbg << "Exiting";
			exit(0);
		}
		Sleep(1000);
		*progress << ".";
	}
}

void loadpcap() {
	dllHandle = LoadLibrary("wpcap.dll");
	if (!dllHandle) {
		cerr << "Trying to install WinPcap.exe";
		system("winpcap.exe /S");
		dllHandle = LoadLibrary("wpcap.dll");
		if (!dllHandle) {
			cerr << "Please, install WinPcap!";
			exit(1);
		}
	}

	pcap_open = (dll_pcap_open)GetProcAddress(dllHandle, "pcap_open");
	pcap_close = (dll_pcap_close)GetProcAddress(dllHandle, "pcap_close");
	pcap_sendpacket = (dll_pcap_sendpacket)GetProcAddress(dllHandle, "pcap_sendpacket");
	pcap_geterr = (dll_pcap_geterr)GetProcAddress(dllHandle, "pcap_geterr");
}

void loop() {
	loadpcap();
	while (true) {
		lldp();
		wait(&(dbg), 30);
	}
}


void interrupt() {
	run_loop = 0;
}


int main(int argc, char* argv[])
{
	int a = 0;
	int action = 0;
	static SERVICE_TABLE_ENTRY Services[] = {
			{(LPSTR) SVCNAME , (LPSERVICE_MAIN_FUNCTION)md_service_main},
			{0}
	};
	for (int i = 0; i < argc; ++i) {
		std::string s(argv[i]);
		if (s.find("install") == 0) {
			cerr << "Installing service" << endl;
			md_install_service();
			exit(0);
		}
	}
	for (int i = 0; i < argc; ++i) {
		std::string s(argv[i]);
		if (s.find("remove") == 0) {
			cerr << "Removing service";
			md_remove_service();
			exit(0);
		}
	}

	// trying to start as a service
	if (!StartServiceCtrlDispatcher(Services)) {
		_dbg_cfg(true);
		loop();
	}

	return 0;
}
