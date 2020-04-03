import "pe"
rule APT_DarkHydrus_Jul18_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-28"
    description = "Detects strings found in malware samples in APT report in DarkHydrus"
    family = "None"
    hacker = "None"
    hash1 = "c8b3d4b6acce6b6655e17255ef7a214651b7fc4e43f9964df24556343393a1a3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Ws2_32.dll" fullword ascii
    $s3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and (
    pe.imphash() == "478eacfbe2b201dabe63be53f34148a5" or
    all of them
}