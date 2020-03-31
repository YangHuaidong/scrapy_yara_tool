rule TeleBots_IntercepterNG {
  meta:
    author = Spider
    comment = None
    date = 2016-12-14
    description = Detects TeleBots malware - IntercepterNG
    family = None
    hacker = None
    hash1 = 5f9fef7974d37922ac91365588fbe7b544e13abbbde7c262fe30bade7026e118
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://goo.gl/4if3HG
    threatname = TeleBots[IntercepterNG
    threattype = IntercepterNG.yar
  strings:
    $s1 = "Usage: %s iface_num\\dump [mode] [w] [-gw] [-t1 ip]" fullword ascii
    $s2 = "Target%d found: %s - [%.2X-%.2X-%.2X-%.2X-%.2X-%.2X]" fullword ascii
    $s3 = "3: passwords + files, no arp poison" fullword ascii
    $s4 = "IRC Joining Keyed Channel intercepted" fullword ascii
    $s5 = "-tX - set target ip" fullword ascii
    $s6 = "w - save session to .pcap dump" fullword ascii
    $s7 = "example: %s 1 1 -gw 192.168.1.1 -t1 192.168.1.3 -t2 192.168.1.5" fullword ascii
    $s8 = "ORACLE8 DES Authorization intercepted" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 4 of them )
}