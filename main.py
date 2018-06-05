#!/usr/bin/python3

import re
import binascii
import struct
from crc32c import crc, crc_update, crc_finalize, CRC_INIT
from collections import namedtuple
import sys

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

# records= \
# """ * 33:33:ff:de:ee:3e   -1 [....] ( 67) 82:39:e1:58:ca:cb ( 71) (0x3ca83da5)
#    01:00:5e:00:00:01   -1 [....] ( 67) 82:39:e1:58:ca:cb ( 71) (0x3ca83da5)
#  * 64:66:b3:de:ee:3e    0 [....] ( 67) 82:39:e1:58:ca:cb ( 71) (0xeb2fdd7a)
#  * 64:66:b3:de:ee:3e   -1 [....] ( 67) 82:39:e1:58:ca:cb ( 71) (0x3ca83da5)
#    33:33:00:00:00:01   -1 [....] ( 67) 82:39:e1:58:ca:cb ( 71) (0x3ca83da5)"""

with open(sys.argv[1]) as f:
    lines = f.read().split('\n')
    lines.remove('')
    records = '\n'.join(lines)

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

def tt_global_crc_entry(entry):
    flags = get_flag_repr(entry.flags)
    if flags & BATADV_TT_CLIENT_ROAM:
        return None

    if flags & BATADV_TT_CLIENT_TEMP:
        return None

    if entry.vid == -1:
        vid = int('0000', 16)
    else:
        vid = entry.vid + int('8000', 16)

    tmp_vid = struct.pack('!H', vid) # equivalent to htons()
    c = crc_update(CRC_INIT, tmp_vid)

    tmp_flags = struct.pack('B', flags & SYNCED_FLAGS)
    c = crc_update(c, tmp_flags)

    tmp_client = parse_mac(entry.client)
    c = crc_update(c, tmp_client)
    print(tmp_client)

    return crc_finalize(c)

def tt_global_crc(records, orig, vid):
    # orig as a str
    c = 0
    official_crc = None
    cnt_records = 0

    for record in records.split('\n'):
        entry = read_tt_global(record)

        if entry.originator != orig:
            continue

        if entry.vid != vid:
            continue

        official_crc = int(entry.crc, 16)

        # print(entry)
        # print(entry.client)
        # print(parse_mac(entry.client))
        # print(get_flag_repr(entry.flags))

        tmp_crc = tt_global_crc_entry(entry)

        if tmp_crc is None:
            # client is roaming or temp
            continue

        cnt_records += 1
        c ^= tmp_crc

    #print("0x%x" % c)
    return c, official_crc, cnt_records

def unique(l):
    return list(set(l))

def get_originators(records):
    originators = []

    for record in records.split('\n'):
        entry = read_tt_global(record)

        originators += [entry.originator]
        originators = unique(originators)

    return originators

def get_vids(records, orig):
    vids = []

    for record in records.split('\n'):
        entry = read_tt_global(record)

        if entry.originator != orig:
            continue

        vids += [entry.vid]
        vids = unique(vids)

    return vids

#for orig in [get_originators(records)[0]]:
n = 0
for orig in get_originators(records):
    #if orig != "ba:a5:2a:91:ff:93":
    #    continue
    n += 1
    #if n > 10:
    #    break
    for vid in get_vids(records, orig):
        locally_calculated, official, cnt = tt_global_crc(records, orig, vid)
        if locally_calculated != official:
            print('o:', orig, "%4d" % vid, "records:", cnt, "fail", "0x%x" % locally_calculated, "!=", "0x%x" % official)
            #print("0x%x" % official, "0x%x" % locally_calculated)
        else:
            print('o:',orig, "%4d" % vid, "records:", cnt,"ok", "0x%x" % locally_calculated)

# print()
# print(get_vids(records, '82:39:e1:58:ca:cb'))
# print("0x%x" % tt_global_crc(records, "82:39:e1:58:ca:cb", -1))
# print("0x%x" % tt_global_crc(records, "82:39:e1:58:ca:cb", 0))
