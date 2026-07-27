#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <utility>

struct convoKey {
    uint32_t ipSource;
    uint32_t ipDest;
    uint16_t portSource;
    uint16_t portDest;
    uint8_t protocol;
    
    
    bool operator==(const convoKey& b) const {
        return ipSource == b.ipSource &&
               ipDest == b.ipDest &&
               portSource == b.portSource &&
               portDest == b.portDest &&
               protocol == b.protocol;
    }
};

namespace std {
    template<> struct hash<convoKey> {
        size_t operator()(const convoKey& k) const {
            size_t h = std::hash<uint32_t>{}(k.ipSource);
            h = h*31 + std::hash<uint32_t>{}(k.ipDest);
            h = h*31 + k.portSource;
            h = h*31 + k.portDest;
            h = h*31 + k.protocol;
            return h;
        }
    };
}

struct convoStats { uint64_t packets = 0; uint64_t bytes = 0; };
std::unordered_map<convoKey, convoStats> convo;

//Read the file format field.
static uint32_t read32Bit(const std::vector<uint8_t>& file, size_t at, bool swap) {
    uint32_t v;
    std::memcpy(&v, file.data() + at, 4);
    if (swap) {
        v =((v & 0x000000FF) << 24) |
           ((v & 0x0000FF00) << 8)  |
           ((v & 0x00FF0000) >> 8)  |
           ((v & 0xFF000000) >> 24);
    }
    return v;
}

//Read the packet fields.
static uint16_t read16Bit(const std::vector<uint8_t>& file, size_t at) {
    return (uint16_t(file[at]) << 8) | uint16_t(file[at + 1]);
}

static void printIp(uint32_t ip) {
    printf("%u.%u.%u.%u", (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
}

int main (int argc, char* argv[]) {
    // Grabs the header(8 bit)
    if (argc < 2) {
        fprintf(stderr, "Failed. %s<file.pcap>\n", argv[0]);
        return 1;
    }
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) {
        fprintf(stderr, "Failed. Cannot open %s\n", argv[1]);
        return 1;
    }
    std::streamsize size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> v(size);
    file.read(reinterpret_cast<char*>(v.data()), size);
    if (v.size() < 24) {
        fprintf(stderr, "Failed. PCAP Header is at least 24 bytes.");
        return 1;
    }

    //Check the magic number and see if byte swap is needed. PCAPNG isn't possible tho.
    uint32_t magic = read32Bit(v, 0, false);
    bool swap;
    if (magic == 0xA1B2C3D4 || magic == 0xA1B23C4D) {
        swap = false;
    } else if (magic == 0xD4C3B2A1 || magic == 0x4D3CB2A1) {
        swap = true;
    } else if (magic ==0x0A0D0D0A) {
        fprintf(stderr, "This seems to be a PCAPNG file, please convert to classic PCAP.\n");
        return 1;
    } else {
        fprintf(stderr, "Not a PCAP file.\n");
        return 1;
    }

    //Start at the global header(24 byte) and traverse the packets.
    size_t position = 24;
    uint32_t layer = read32Bit(v, 20, swap);
    if (layer != 1) {
        fprintf(stderr, "Only ethernet is supported. This layer is %u.\n", layer);
        return 1;
    }
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t ipv4Count = 0;
    uint64_t ipv6Count = 0;
    uint64_t otherCount = 0;
    while (position + 16 <= v.size()) {
        uint32_t length = read32Bit(v, position + 8, swap);
        if (position + 16 + length > v.size()) {
            break;
        }
        if (length >= 14) {
            uint16_t etherType = read16Bit(v, position + 16 + 12);
            if (etherType == 0x0800) {
                if (length >= 34) {
                    size_t ipStart = position + 16 + 14;
                    uint8_t ipInfo = v[ipStart];
                    uint8_t version = ipInfo >> 4;
                    uint8_t ipHeaderLength = (ipInfo & 0x0F) * 4;
                    if (ipHeaderLength < 20) {
                        packets++;
                        bytes += length;
                        position+= 16 + length;
                        continue;
                    }
                    size_t transportStart = ipStart + ipHeaderLength;
                    uint32_t layer = read32Bit(v, 20, swap);
                    uint32_t sourceIp = (uint32_t(v[ipStart+12]) << 24) | (uint32_t(v[ipStart+13]) << 16) 
                    | (uint32_t(v[ipStart+14]) << 8) | uint32_t(v[ipStart+15]);
                    uint32_t destinationIp = (uint32_t(v[ipStart+16]) << 24) | (uint32_t(v[ipStart+17]) << 16)
                    | (uint32_t(v[ipStart+18]) << 8) |  uint32_t(v[ipStart+19]);
                    uint8_t protocol = v[ipStart+9];
                    if ((protocol == 6 || protocol == 17) && length >= 38) {
                        uint16_t sourcePort = read16Bit(v, transportStart);
                        uint16_t destinationPort = read16Bit(v, transportStart + 2);
                        auto pairSource = std::pair<uint32_t, uint16_t>(sourceIp, sourcePort);
                        auto pairDestination = std::pair<uint32_t, uint16_t>(destinationIp, destinationPort);
                        convoKey key;
                        if (pairSource <= pairDestination) {
                            key.ipSource = sourceIp;
                            key.portSource = sourcePort;
                            key.ipDest = destinationIp;
                            key.portDest = destinationPort;
                        } else {
                            key.ipSource = destinationIp;
                            key.portSource = destinationPort;
                            key.ipDest = sourceIp;
                            key.portDest = sourcePort;
                        }
                        key.protocol = protocol;
                        convo[key].packets++;
                        convo[key].bytes += length;
                    }

                }
                ipv4Count++;
            } else if (etherType == 0x86DD) {
                ipv6Count++;
            } else {
                otherCount++;
            }
        }
        packets++;
        bytes+=length;
        position += 16 + length;
    }
    printf("Packets Amount:    %llu\n", (unsigned long long) packets);
    printf("Bytes Amount:      %llu\n", (unsigned long long) bytes);
    printf("ipv4Count Amount:  %llu\n", (unsigned long long) ipv4Count);
    printf("ipv6Count Amount:  %llu\n", (unsigned long long) ipv6Count);
    printf("otherCount Amount: %llu\n", (unsigned long long) otherCount);
    printf("Conversations: %zu\n", convo.size());
    for (const auto& [key, stats] : convo) {
        printf("  ");
        printIp(key.ipSource);
        printf(":%u <-> ", key.portSource);
        printIp(key.ipDest);
        printf(":%u  protocol %u  packets=%llu bytes=%llu\n",
           key.portDest, key.protocol,
           (unsigned long long)stats.packets,
           (unsigned long long)stats.bytes);
    }
}