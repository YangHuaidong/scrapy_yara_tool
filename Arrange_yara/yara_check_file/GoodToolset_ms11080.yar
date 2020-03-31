rule GoodToolset_ms11080 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file ms11080.exe
    family = None
    hacker = None
    hash = f0854c49eddf807f3a7381d3b20f9af4a3024e9f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = GoodToolset[ms11080
    threattype = ms11080.yar
  strings:
    $s1 = "[*] command add user 90sec 90sec" fullword ascii
    $s2 = "\\ms11080\\Debug\\ms11080.pdb" fullword ascii
    $s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
    $s4 = "[*] Add to Administrators success" fullword ascii
    $s5 = "[*] User has been successfully added" fullword ascii
    $s6 = "[>] ms11-08 Exploit" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}