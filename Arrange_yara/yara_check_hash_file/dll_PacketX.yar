rule dll_PacketX {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library
    family = None
    hacker = None
    hash = 3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    score = 50
    threatname = dll[PacketX
    threattype = PacketX.yar
  strings:
    $s9 = "[Failed to load winpcap packet.dll." wide
    $s10 = "PacketX Version" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}