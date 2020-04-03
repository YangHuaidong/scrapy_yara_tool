rule Sofacy_Fysbis_ELF_Backdoor_Gen2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-02-13"
    description = "Detects Sofacy Fysbis Linux Backdoor"
    family = "None"
    hacker = "None"
    hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
    hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
    hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "RemoteShell" ascii
    $s2 = "basic_string::_M_replace_dispatch" fullword ascii
    $s3 = "HttpChannel" ascii
  condition:
    uint16(0) == 0x457f and filesize < 500KB and all of them
}