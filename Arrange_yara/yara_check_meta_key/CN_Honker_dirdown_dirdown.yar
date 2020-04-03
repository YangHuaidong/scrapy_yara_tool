rule CN_Honker_dirdown_dirdown {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file dirdown.exe"
    family = "None"
    hacker = "None"
    hash = "7b8d51c72841532dded5fec7e7b0005855b8a051"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\Decompress\\obj\\Release\\Decompress.pdb" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "Decompress.exe" fullword wide
    $s5 = "Get8Bytes" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 45KB and all of them
}