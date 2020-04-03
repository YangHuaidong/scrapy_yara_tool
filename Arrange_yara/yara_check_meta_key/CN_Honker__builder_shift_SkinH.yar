rule CN_Honker__builder_shift_SkinH {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - from files builder.exe, shift.exe, SkinH.exe"
    family = "None"
    hacker = "None"
    hash0 = "6b5a84cdc3d27c435d49de3f68872d015a5aadfc"
    hash1 = "ee127c1ea1e3b5bf3d2f8754fabf9d1101ed0ee0"
    hash2 = "d593f03ae06e54b653c7850c872c0eed459b301f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "lipboard" fullword ascii
    $s2 = "uxthem" fullword ascii
    $s3 = "ENIGMA" fullword ascii
    $s4 = "UtilW0ndow" fullword ascii
    $s5 = "prog3am" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 6075KB and all of them
}