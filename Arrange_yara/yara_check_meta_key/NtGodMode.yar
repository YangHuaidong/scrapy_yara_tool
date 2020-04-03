rule NtGodMode {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file NtGodMode.exe"
    family = "None"
    hacker = "None"
    hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "to HOST!" fullword ascii
    $s1 = "SS.EXE" fullword ascii
    $s5 = "lstrlen0" fullword ascii
    $s6 = "Virtual" fullword ascii  /* Goodware String - occured 6 times */
    $s19 = "RtlUnw" fullword ascii /* Goodware String - occured 1 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 45KB and all of them
}