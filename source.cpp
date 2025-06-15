#include <pcap.h>
#include <iostream>
#include <csignal>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <ctime>
#include <netinet/ip6.h>  // Include this header for ip6_hdr

// Global flag to control the packet capture loop
volatile sig_atomic_t keep_running = 1;

// Class to handle logging
class Logger {
public:
    std::ofstream log_file;
    std::ofstream payload_file;

    Logger() : log_file("packets.log", std::ios::out | std::ios::app), 
               payload_file("payloads.log", std::ios::out | std::ios::app) {}

    void log_packet_details(const u_char *data, int length) {
        log_file << "Packet Length: " << length << " bytes\nData: ";
        print_hex(data, length);
        log_file << std::endl;
    }

    void log_payload(const u_char *payload, int size) {
        if (size > 0 && payload != nullptr) {
            payload_file << "Payload (size: " << size << " bytes): ";
            print_hex(payload, size);
            payload_file << std::endl;
        } else {
            payload_file << "No payload or invalid size." << std::endl;
        }
    }

private:
    void print_hex(const u_char *data, int length) {
        for (int i = 0; i < length; i++) {
            log_file << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
            if ((i + 1) % 16 == 0) {
                log_file << "\n";
            }
        }
        log_file << std::dec << "\n";
    }
};

// Class to manage network connections and packet capture
class NetworkConnection {
public:
    pcap_t *handle;

    NetworkConnection() : handle(nullptr) {}

    bool open_device(const char *dev_name, char *errbuf) {
        handle = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);
        return handle != nullptr;
    }

    void close_device() {
        if (handle != nullptr) {
            pcap_close(handle);
        }
    }

    bool set_filter(const char *filter_exp) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            pcap_freecode(&fp);
            return false;
        }
        pcap_freecode(&fp);
        return true;
    }
};

// Rule struct definition
struct Rule {
    std::string action;
    std::string protocol;
    std::string src_ip;
    int src_port;
    std::string dst_ip;
    int dst_port;
    std::string content;
    int sid;
};

// Class for signature-based detection
class SignatureDetection {
public:
    bool match_rule(const Rule &rule, const struct ip *ip_header, const struct tcphdr *tcp_header, const uint8_t *payload, int payload_size) {
        std::string src_ip = inet_ntoa(ip_header->ip_src);
        std::string dst_ip = inet_ntoa(ip_header->ip_dst);
        int src_port = ntohs(tcp_header->source);
        int dst_port = ntohs(tcp_header->dest);

        return match_ip(rule.src_ip, src_ip) && match_ip(rule.dst_ip, dst_ip) &&
               match_port(rule.src_port, src_port) && match_port(rule.dst_port, dst_port) &&
               match_content(rule.content, payload, payload_size);
    }

private:
    bool match_ip(const std::string &rule_ip, const std::string &packet_ip) {
        return rule_ip == "any" || rule_ip == packet_ip;
    }

    bool match_port(int rule_port, int packet_port) {
        return rule_port == 0 || rule_port == packet_port;
    }

    bool match_content(const std::string &content, const uint8_t *payload, int payload_size) {
        if (content.empty()) return true;
        std::string payload_str(reinterpret_cast<const char*>(payload), payload_size);
        return payload_str.find(content) != std::string::npos;
    }
};

// Class to analyze packets
class PacketAnalyzer {
public:
    void analyze_packet(const u_char *packet, const struct pcap_pkthdr *header, Logger &logger) {
        struct ether_header *eth_header = (struct ether_header *) packet;

        std::cout << "Received Packet Size: " << header->len << " bytes\n";
        std::cout << "EtherType: 0x" << std::hex << ntohs(eth_header->ether_type) << std::dec << std::endl;

        logger.log_packet_details(packet, header->len);

        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            process_ipv4_packet(packet, header, logger);
        } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
            process_ipv6_packet(packet, header, logger);
        } else {
            std::cout << "Not an IP packet" << std::endl;
        }
    }

private:
    void process_ipv4_packet(const u_char *packet, const struct pcap_pkthdr *header, Logger &logger) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    std::cout << "IPv4 packet from " << src_ip << " to " << dst_ip << std::endl;

    logger.log_packet_details(packet, header->len);

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
        const u_char *payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->doff * 4);
        int payload_size = header->len - (sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->doff * 4));

        if (payload_size > 0) {
            std::cout << "TCP Payload Size: " << payload_size << " bytes" << std::endl;
            logger.log_payload(payload, payload_size);
        } else {
            std::cout << "No TCP Payload" << std::endl;
        }
    }
}


    void process_ipv6_packet(const u_char *packet, const struct pcap_pkthdr *header, Logger &logger) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        std::cout << "IPv6 packet from " << src_ip << " to " << dst_ip << std::endl;

        logger.log_packet_details(packet, header->len);

        // Add handling for IPv6 payload if needed
    }
};

// Signal handler for graceful termination
void handle_signal(int signal) {
    keep_running = 0;
}

// Callback function for pcap_dispatch
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    PacketAnalyzer *analyzer = reinterpret_cast<PacketAnalyzer *>(user_data);
    Logger *logger = reinterpret_cast<Logger *>(user_data + sizeof(PacketAnalyzer));
    analyzer->analyze_packet(packet, header, *logger);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    int duration = 60; // Capture duration in seconds

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // Check if the specified device is available
    dev = alldevs;
    while (dev) {
        if (strcmp(dev->name, argv[1]) == 0) {
            break;
        }
        dev = dev->next;
    }

    if (dev == nullptr) {
        std::cerr << "No such device found: " << argv[1] << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    NetworkConnection network_connection;
    if (!network_connection.open_device(dev->name, errbuf)) {
        std::cerr << "Couldn't open device " << dev->name << ": " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 2;
    }

    if (!network_connection.set_filter("ip")) {
        std::cerr << "Error setting filter" << std::endl;
        network_connection.close_device();
        pcap_freealldevs(alldevs);
        return 2;
    }

    signal(SIGINT, handle_signal);

    Logger logger;
    PacketAnalyzer packet_analyzer;

    time_t start_time = time(nullptr);
    while (keep_running && difftime(time(nullptr), start_time) < duration) {
        std::cout << "Attempting to capture packet..." << std::endl;
        int packet_count = pcap_dispatch(network_connection.handle, 1, packet_handler, reinterpret_cast<u_char *>(&packet_analyzer));
        
        if (packet_count == 0) {
            std::cout << "No packet captured, timeout or no packets available." << std::endl;
        } else if (packet_count < 0) {
            std::cerr << "Error in pcap_dispatch" << std::endl;
            keep_running = 0;
        } else {
            std::cout << "Captured " << packet_count << " packet(s)." << std::endl;
        }
    }

    network_connection.close_device();
    pcap_freealldevs(alldevs);
    return 0;
}