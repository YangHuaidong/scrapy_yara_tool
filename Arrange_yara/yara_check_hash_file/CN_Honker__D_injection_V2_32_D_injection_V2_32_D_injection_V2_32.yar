rule CN_Honker__D_injection_V2_32_D_injection_V2_32_D_injection_V2_32 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - from files D_injection_V2.32.exe, D_injection_V2.32.exe, D_injection_V2.32.exe
    family = D
    hacker = None
    hash0 = 3a000b976c79585f62f40f7999ef9bdd326a9513
    hash1 = 3a000b976c79585f62f40f7999ef9bdd326a9513
    hash2 = 3a000b976c79585f62f40f7999ef9bdd326a9513
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    super_rule = 1
    threatname = CN[Honker]/.D.injection.V2.32.D.injection.V2.32.D.injection.V2.32
    threattype = Honker
  strings:
    $s1 = "upfile.asp " fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "[wscript.shell]" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "XP_CMDSHELL" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "[XP_CMDSHELL]" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "http://d99net.3322.org" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 10000KB and 4 of them
}