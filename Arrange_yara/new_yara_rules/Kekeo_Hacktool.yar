rule Kekeo_Hacktool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-21"
    description = "Detects Kekeo Hacktool"
    family = "None"
    hacker = "None"
    hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
    hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/gentilkiwi/kekeo/releases"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[ticket %u] session Key is NULL, maybe a TGT without enough rights when WCE dumped it." fullword wide
    $x2 = "ERROR kuhl_m_smb_time ; Invalid! Command: %02x - Status: %08x" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) ) )
}