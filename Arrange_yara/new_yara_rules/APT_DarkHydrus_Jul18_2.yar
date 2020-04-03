rule APT_DarkHydrus_Jul18_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-28"
    description = "Detects strings found in malware samples in APT report in DarkHydrus"
    family = "None"
    hacker = "None"
    hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "windir" fullword ascii /* Goodware String - occured 47 times */
    $s6 = "temp.dll" fullword ascii /* Goodware String - occured 3 times */
    $s7 = "libgcj-12.dll" fullword ascii /* Goodware String - occured 3 times */
    $s8 = "%s\\System32\\%s" fullword ascii /* Goodware String - occured 4 times */
    $s9 = "StartW" fullword ascii /* Goodware String - occured 5 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and all of them
}