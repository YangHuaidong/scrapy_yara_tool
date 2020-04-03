import "pe"
rule MAL_Ransomware_Wadhrama {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-07"
    description = "Detects Wadhrama Ransomware via Imphash"
    family = "None"
    hacker = "None"
    hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and pe.imphash() == "f86dec4a80961955a89e7ed62046cc0e"
}