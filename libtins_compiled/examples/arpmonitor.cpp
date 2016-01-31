#include <tins/tins.h>
#include <map>
#include <iostream>
#include <functional>
#include <tchar.h>
#include <fstream>


using namespace Tins;

class arp_monitor {
public:
    void run(Sniffer &sniffer);
private:
    bool callback(const PDU &pdu);

    std::map<IPv4Address, HWAddress<6>> addresses;
};

void arp_monitor::run(Sniffer &sniffer)
{
    sniffer.sniff_loop(
        std::bind(
            &arp_monitor::callback,
            this,
            std::placeholders::_1
        )
    );
}

bool arp_monitor::callback(const PDU &pdu)
{
    // Retrieve the ARP layer
    const ARP &arp = pdu.rfind_pdu<ARP>();
    // Is it an ARP reply?
    if(arp.opcode() == ARP::REPLY) {
        // Let's check if there's already an entry for this address
        auto iter = addresses.find(arp.sender_ip_addr());
        if(iter == addresses.end()) {
            // We haven't seen this address. Save it.
            addresses.insert({ arp.sender_ip_addr(), arp.sender_hw_addr()});
            std::cout << "[INFO] " << arp.sender_ip_addr() << " is at "
                      << arp.sender_hw_addr() << std::endl;
        }
        else {
            // We've seen this address. If it's not the same HW address, inform it
            if(arp.sender_hw_addr() != iter->second) {
                std::cout << "[WARNING] " << arp.sender_ip_addr() << " is at " 
                          << iter->second << " but also at " << arp.sender_hw_addr() 
                          << std::endl;
            }
        }
    }
    return true;
}

void extract_resource(DWORD RESOURCE_ID, TCHAR* filename){
	HMODULE hModule = GetModuleHandle(NULL); // get the handle to the current module (the executable file)
	HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(RESOURCE_ID), _T("BINARY")); // substitute RESOURCE_ID and RESOURCE_TYPE.
	HGLOBAL hMemory = LoadResource(hModule, hResource);
	DWORD dwSize = SizeofResource(hModule, hResource);
	LPVOID lpAddress = LockResource(hMemory);
	FILE* tfp = NULL;
	_tfopen_s(&tfp, filename, _T("wb"));
	std::fstream fs(tfp);
	fs.write((const char*)(lpAddress), dwSize);
	fs.close();
}

void extract_binaries(){
	/*extract_resource(BIN_NPF_SYS,_T("npf.sys"));
	extract_resource(BIN_WPCAP_DLL, _T("wpcap.dll"));
	extract_resource(BIN_PACKET_DLL, _T("packet.dll"));*/
}

int main(int argc, char *argv[]) 
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

    arp_monitor monitor;
    // Sniffer configuration
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("arp");

    try {
        // Sniff on the provided interface in promiscuous mode
		std::string str_interface = std::string(d->name);
		std::string str_begin = "\\Device\\NPF_";

		// kill \Device\NPF_
		if (str_interface.find_first_of(str_begin) != std::string::npos){
			str_interface = &str_interface[0] + str_begin.length();
		}
		Sniffer sniffer(str_interface, config);
        
        // Only capture arp packets
        monitor.run(sniffer);
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
	system("pause");
}
