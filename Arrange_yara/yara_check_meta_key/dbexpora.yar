rule dbexpora {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file dbexpora.dll"
    family = "None"
    hacker = "None"
    hash = "b55b007ef091b2f33f7042814614564625a8c79f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
    $s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
    $s13 = "ORACommand *" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 835KB and all of them
}