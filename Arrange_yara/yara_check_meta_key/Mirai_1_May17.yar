rule Mirai_1_May17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-05-12"
    description = "Detects Mirai Malware"
    family = "None"
    hacker = "None"
    hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
    hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
    hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 5000KB and all of them )
}