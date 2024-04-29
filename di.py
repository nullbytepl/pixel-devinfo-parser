# Google Pixel devinfo parser 1.0
# By Kamila Wojciechowska
#
# SPDX-License-Identifier: Apache-2.0

import sys
import os
import struct

'''
struct devinfo_ab_slot_data_t {
    uint8_t retry_count;
    uint8_t unbootable : 1;
    uint8_t successful : 1;
    uint8_t active : 1;
    uint8_t fastboot_ok : 1;
    uint8_t : 4;
    uint8_t unused[2];
};

typedef struct {
    //const size_t DEVINFO_AB_SLOT_COUNT = 2;
    devinfo_ab_slot_data_t slots[2];
} devinfo_ab_data_t;

struct devinfo_t {
    uint32_t magic; //const uint32_t DEVINFO_MAGIC = 0x49564544; - "DEVI"
    uint16_t ver_major;
    uint16_t ver_minor;
    uint8_t unused[32];
    uint8_t board_id[3]; // reverse engineered
    uint8_t board_rev[3]; // reverse engineered
    uint8_t unused1[2];
    devinfo_ab_data_t ab_data;
    uint8_t unused2[72];  // use remaining up to complete 128 bytes
} devinfo_t;
'''

def main():
    # open the file
    if len(sys.argv) < 2:
        print("Usage: %s <devinfo file>" % sys.argv[0])
        sys.exit(1)
    
    devinfo_file = sys.argv[1]

    if not os.path.isfile(devinfo_file):
        print("Error: %s does not exist" % devinfo_file)
        sys.exit(1)

    with open(devinfo_file, "rb") as f:
        devinfo = f.read()
        # check magic: "DEVI"
        if devinfo[0:4] != b"DEVI":
            print("Error: %s is not a devinfo file" % devinfo_file)
            sys.exit(1)
        # print version
        ver_major = struct.unpack("<H", devinfo[4:6])[0]
        ver_minor = struct.unpack("<H", devinfo[6:8])[0]
        print("Devinfo version: %d.%d" % (ver_major, ver_minor))

        if ver_major != 3:
            print("WARNING: devinfo version is not 3.x, this script may not work correctly")

        # print raw board id and rev (bytes, hex)
        # First two bytes of board_id indicate the project (print as hex)
        # Last byte of board_id is the stage code:
        # 0x00: ?, 0x01: DEV, 0x02: PROTO, 0x03: EVT, 0x04: DVT, 0x05: PVT, 0x06: MP
        # This should be displayed as a string
        # The board rev can be parsed as follows:
        # 0xAABBCC
        # Printable rev: AA.BB
        # CC is the "variant", which is only important when it's not 0x00

        STAGE_MAPPING = {
            0x01: "DEV",
            0x02: "PROTO",
            0x03: "EVT",
            0x04: "DVT",
            0x05: "PVT",
            0x06: "MP"
        }

        stage_str = STAGE_MAPPING[devinfo[42]] or "Unknown"

        print("Device: %s%s.%s" % (stage_str, devinfo[43], devinfo[44]))
        print("  Board ID: 0x%s," % devinfo[40:43].hex())
        print("    Project: 0x%s" % devinfo[40:42].hex())
        print("    Stage: %s" % stage_str)
        print("  Board Rev: 0x%s" % devinfo[43:46].hex())
        print("    Printable rev: %s.%s" % (devinfo[43], devinfo[44]))
        print("    Variant: 0x%02x" % devinfo[45])

        # print slots
        print("AB slots:")
        print("  Slot A:")
        print("    Retry count: %d" % devinfo[48])
        print("    Unbootable: %d" % (devinfo[49] & 0x1))
        print("    Successful: %d" % ((devinfo[49] >> 1) & 0x1))
        print("    Active: %d" % ((devinfo[49] >> 2) & 0x1))
        print("    Fastboot ok: %d" % ((devinfo[49] >> 3) & 0x1))
        print("  Slot B:")
        print("    Retry count: %d" % devinfo[52])
        print("    Unbootable: %d" % (devinfo[53] & 0x1))
        print("    Successful: %d" % ((devinfo[53] >> 1) & 0x1))
        print("    Active: %d" % ((devinfo[53] >> 2) & 0x1))
        print("    Fastboot ok: %d" % ((devinfo[53] >> 3) & 0x1))

        # Print PS tags
        # PS tags are stored like this:
        # > uint32_t magic; "DIUS" or "DIFR"
        # > uint32_t full_tag_len;
        # > uint32_t tag_key_len;
        # > [tag_key_len] tag_key;
        # > [full_tag_len-tag_key_len] tag_value;
        # 
        # We print until we don't encounter the magic
        #
        # If full_tag_len is not 0, but tag_key_len is 0, then the particular tag is padding
        # If tag_key_len > full_tag_len, then the tag is corrupted/invalid
        # If the tag value contains non-printable characters, display it as hex
        #
        # At the 4096 boundary are ENV tags, which are exactly the same as PS tags, but are writable
        print("PS (factory written) tags:")
        offset = 128
        while devinfo[offset:offset+4] in [b"DIUS", b"DIFR"]:
            if offset == 4096:
                print("PS (ENV) tags:")

            magic = devinfo[offset:offset+4].decode("utf-8")
            full_tag_len = struct.unpack("<I", devinfo[offset+4:offset+8])[0]
            tag_key_len = struct.unpack("<I", devinfo[offset+8:offset+12])[0]
            tag_key = devinfo[offset+12:offset+12+tag_key_len].decode("utf-8")
            tag_value = devinfo[offset+12+tag_key_len:offset+12+full_tag_len].decode("utf-8")
            if (tag_key_len > full_tag_len):
                print("  (corrupted/invalid tag)") 
            elif (full_tag_len != 0) and (tag_key_len == 0):
                print("  (padding: %d bytes)" % full_tag_len)
            else:
                # check if tag value is printable (ignore \0)
                if not all([32 <= ord(c) <= 126 or c == "\0" for c in tag_value]):
                    print("  %s: (0x%s)" % (tag_key, tag_value.encode("utf-8").hex()))
                else:
                    print("  %s: %s" % (tag_key, tag_value))

            offset += full_tag_len + 12

if __name__ == "__main__":
    main()