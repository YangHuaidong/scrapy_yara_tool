rule Guilin_veterans_cookie_spoofing_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
    family = "None"
    hacker = "None"
    hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "kernel32.dll^G" fullword ascii
    $s1 = "\\.Sus\"B" fullword ascii
    $s4 = "u56Load3" fullword ascii
    $s11 = "O MYTMP(iM) VALUES (" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}