rule CN_Honker_getlsasrvaddr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file getlsasrvaddr.exe - WCE Amplia Security"
    family = "None"
    hacker = "None"
    hash = "a897d5da98dae8d80f3c0a0ef6a07c4b42fb89ce"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s8 = "pingme.txt" fullword ascii /* PEStudio Blacklist: strings */
    $s16 = ".\\lsasrv.pdb" fullword ascii
    $s20 = "Addresses Found: " fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}