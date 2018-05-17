#!/usr/bin/python3

import re
import binascii
import struct
from crc32c import crc, crc_update, crc_finalize, CRC_INIT
from collections import namedtuple

# Flag definitions
# remote flags
BATADV_TT_CLIENT_DEL     = (1 << 0)
BATADV_TT_CLIENT_ROAM    = (1 << 1)

# remote & crc flags
BATADV_TT_CLIENT_WIFI    = (1 << 4)
BATADV_TT_CLIENT_ISOLA	 = (1 << 5)

# local flags
BATADV_TT_CLIENT_NOPURGE = (1 << 8)
BATADV_TT_CLIENT_NEW     = (1 << 9)
BATADV_TT_CLIENT_PENDING = (1 << 10)
BATADV_TT_CLIENT_TEMP	 = (1 << 11)

SYNCED_FLAGS = BATADV_TT_CLIENT_ISOLA | BATADV_TT_CLIENT_WIFI

record="   33:33:00:00:00:01   -1 [.W..] (  4) 5e:1c:3b:6c:a1:3b (  4) (0xce93f3f0)"

TTGlobalEntry = namedtuple('TTGlobalEntry', 'client vid flags originator crc')

def read_tt_global(line):
    m = re.match('^...(.{17})\s([0-9\- ]*)\s\[(....)\]\s\((...)\)\s(.{17})\s\((...)\)\s\(0x([0-9a-f]{8})\)', line)
    assert(m is not None)

    return TTGlobalEntry(
        client = m[1],
        vid = int(m[2]),
        flags = m[3],
        originator = m[5],
        crc = m[7]
    )

def parse_mac(mac_str):
    print(binascii.unhexlify(mac_str.replace(':', '')))
    return binascii.unhexlify(mac_str.replace(':', ''))

def get_flag_repr(flag_str):
    assert(len(flag_str) == 4)
    assert(flag_str[0] == '.' or flag_str[0] == 'R')
    assert(flag_str[1] == '.' or flag_str[1] == 'W')
    assert(flag_str[2] == '.' or flag_str[2] == 'I')
    assert(flag_str[3] == '.' or flag_str[3] == 'T')

    repr = (BATADV_TT_CLIENT_WIFI if 'W' in flag_str else 0) + \
           (BATADV_TT_CLIENT_ISOLA if 'I' in flag_str else 0) + \
           (BATADV_TT_CLIENT_ROAM if 'R' in flag_str else 0) + \
           (BATADV_TT_CLIENT_TEMP if 'T' in flag_str else 0)

    return repr

def tt_global_crc(entry):
    flags = get_flag_repr(entry.flags)
    if flags & BATADV_TT_CLIENT_ROAM:
        return None

    if flags & BATADV_TT_CLIENT_TEMP:
        return None

    tmp_vid = struct.pack('!h', entry.vid) # equivalent to htons()
    c = crc_update(CRC_INIT, tmp_vid)

    tmp_flags = struct.pack('h', flags & SYNCED_FLAGS)
    c = crc_update(c, tmp_flags)

    tmp_client = parse_mac(entry.client) # TODO: reverse byte order?
    c = crc_update(c, tmp_client)

    return crc_finalize(c)


entry = read_tt_global(record)
print(entry)
print(entry.client)
print(parse_mac(entry.client))
print(get_flag_repr(entry.flags))
print(tt_global_crc(entry))
