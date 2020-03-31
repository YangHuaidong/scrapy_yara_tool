rule SUSP_Size_of_ASUS_TuningTool {
  meta:
    author = Spider
    comment = None
    date = 2018-10-17
    description = Detects an ASUS tuning tool with a suspicious size
    family = ASUS
    hacker = None
    hash1 = d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a
    judge = unknown
    noarchivescan = 1
    reference = https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/
    score = 60
    threatname = SUSP[Size]/of.ASUS.TuningTool
    threattype = Size
  strings:
    $s1 = "\\Release\\ASGT.pdb" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and filesize > 70KB and all of them
}