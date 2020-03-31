rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_3_0 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file 3.0.exe
    family = 3389
    hacker = None
    hash = 49b311add0940cf183e3c7f3a41ea6e516bf8992
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/sig.3389.DUBrute.v3.0.RC3.3.0
    threattype = Honker
  strings:
    $s0 = "explorer.exe http://bbs.yesmybi.net" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */
    $s9 = "CryptGenRandom" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 581 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 395KB and all of them
}