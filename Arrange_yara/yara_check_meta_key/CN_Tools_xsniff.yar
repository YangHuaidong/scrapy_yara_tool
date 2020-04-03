rule CN_Tools_xsniff {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file xsniff.exe"
    family = "None"
    hacker = "None"
    hash = "d61d7329ac74f66245a92c4505a327c85875c577"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
    $s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
    $s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
    $s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
    $s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}