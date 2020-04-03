rule CN_Honker_CnCerT_CCdoor_CMD_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll2"
    family = "None"
    hacker = "None"
    hash = "7f3a6fb30845bf366e14fa21f7e05d71baa1215a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "cmd.dll" fullword wide
    $s1 = "cmdpath" fullword ascii
    $s2 = "Get4Bytes" fullword ascii
    $s3 = "ExcuteCmd" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 22KB and all of them
}