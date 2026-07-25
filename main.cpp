#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

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
    double packets = 0;
    double bytes = 0;
    while (position + 16 <= v.size()) {
        uint32_t length = read32Bit(v, position + 8, swap);
        packets++;
        bytes+=length;
        position += 16 + length;
    }
    printf("Packets Amount: %.0f\n", packets);
    printf("Bytes Amount:   %.0f\n", bytes);
}