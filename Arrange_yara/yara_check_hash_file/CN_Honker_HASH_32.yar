rule CN_Honker_HASH_32 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file 32.exe
    family = 32
    hacker = None
    hash = bf4a8b4b3e906e385feab5ea768f604f64ba84ea
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/HASH.32
    threattype = Honker
  strings:
    $s5 = "[Undefined OS version]  Major: %d Minor: %d" fullword ascii
    $s8 = "Try To Run As Administrator ..." fullword ascii /* PEStudio Blacklist: strings */
    $s9 = "Specific LUID NOT found" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 240KB and all of them
}