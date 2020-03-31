rule CN_Honker_T00ls_Lpk_Sethc_v2 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v2.exe
    family = Lpk
    hacker = None
    hash = a995451d9108687b8892ad630a79660a021d670a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/T00ls.Lpk.Sethc.v2
    threattype = Honker
  strings:
    $s1 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "2011-2012 T00LS&RICES" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and all of them
}