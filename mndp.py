#!/usr/bin/env python3

from socket import *
from struct import *
from binascii import hexlify
import sys

import json

from pprint import pprint

def parse_mndp(data):
    entry = {}
    names = ('version', 'ttl', 'checksum')
    for idx, val in enumerate(unpack_from('!BBH', data)):
        entry[names[idx]] = val

    pos = 4
    while pos + 4 < len(data):
        type, length = unpack_from('!HH', data, pos)
        pos += 4

        # MAC
        if type == 1:
            (mac,) = unpack_from('6s', data, pos)
#            for x in mac:
#                pprint(x)
            entry['mac'] = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(x for x in mac)
#            pprint(entry['mac'])

        # Identity
        elif type == 5:
            entry['id'] = data[pos:pos + length].decode("utf-8")

        # Platform
        elif type == 8:
            entry['platform'] = data[pos:pos + length].decode("utf-8")

        # Version
        elif type == 7:
            entry['version'] = data[pos:pos + length].decode("utf-8")

        # uptime?
        elif type == 10:
            (uptime,) = unpack_from('<I', data, pos)
            entry['uptime'] = uptime

        # hardware
        elif type == 12:
            entry['hardware'] = data[pos:pos + length].decode("utf-8")

        # softid
        elif type == 11:
            entry['softid'] = data[pos:pos + length].decode("utf-8")

        # ifname
        elif type == 16:
            entry['ifname'] = data[pos:pos + length].decode("utf-8")

        # ipv4 address
        elif type == 17:
            (ipv4,) = unpack_from('4s', data, pos)
            entry['ipv4'] = "%d.%d.%d.%d" % tuple(x for x in ipv4)

        else:
            entry['unknown-%d' % type] = hexlify(data[pos:pos + length]).decode("utf-8")

        pos += length

    return entry

def mndp_scan():
    cs = socket(AF_INET, SOCK_DGRAM)

    cs.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    cs.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    cs.bind(('', 5678))

    cs.sendto(b'\0\0\0\0', ('255.255.255.255', 5678))

    try:
        entries = {}
        while True:
            (data, src_addr) = cs.recvfrom(1500)
            # ignore the msg we getourselves
#            if data == '\0\0\0\0':
#                continue

            if len(data) < 18:
                continue
            entry = parse_mndp(data)
            print(json.dumps(entry))
#            pprint(entry)
            print("")
#            if entry['mac'] not in entries:
#                print("Reply from:", src_addr, len(data))
#                print(" %(mac)s, ID: %(id)s" % entry)
#                print(" Platform: %(platform)s,  Ver: %(version)s, HW: %(hardware)s, Uptime: %(uptime)d" % entry)
#                print("  SoftID: %(softid)s, IF: %(ifname)s, Platform: %(platform)s" % entry)
#                entries[entry['mac']] = entry



    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    mndp_scan()
