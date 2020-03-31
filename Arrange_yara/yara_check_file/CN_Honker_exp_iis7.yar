rule CN_Honker_exp_iis7 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file iis7.exe
    family = iis7
    hacker = None
    hash = 0a173c5ece2fd4ac8ecf9510e48e95f43ab68978
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/exp.iis7
    threattype = Honker
  strings:
    $s0 = "\\\\localhost" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "iis.run" fullword ascii
    $s3 = ">Could not connecto %s" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "WinSta0\\Default" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 22 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}