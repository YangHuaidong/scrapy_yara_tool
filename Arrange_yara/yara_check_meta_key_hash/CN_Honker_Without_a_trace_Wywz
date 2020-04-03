rule CN_Honker_Without_a_trace_Wywz {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Wywz.exe"
    family = "None"
    hacker = "None"
    hash = "f443c43fde643228ee95def5c8ed3171f16daad8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Symantec\\Norton Personal Firewall\\Log\\Content.log" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "UpdateFile=d:\\tool\\config.ini,Option\\\\proxyIp=127.0.0.1\\r\\nproxyPort=808" ascii /* PEStudio Blacklist: strings */
    $s3 = "%s\\subinacl.exe /subkeyreg \"%s\" /Grant=%s=f /Grant=everyone=f" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 1800KB and all of them
}