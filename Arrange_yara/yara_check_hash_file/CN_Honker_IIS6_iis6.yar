rule CN_Honker_IIS6_iis6 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file iis6.com
    family = iis6
    hacker = None
    hash = f0c9106d6d2eea686fd96622986b641968d0b864
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/IIS6.iis6
    threattype = Honker
  strings:
    $s0 = "GetMod;ul" fullword ascii
    $s1 = "excjpb" fullword ascii
    $s2 = "LEAUT1" fullword ascii
    $s3 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 410 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and all of them
}