rule CN_Honker_smsniff_smsniff {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file smsniff.exe
    family = smsniff
    hacker = None
    hash = 8667a785a8ced76d0284d225be230b5f1546f140
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/smsniff.smsniff
    threattype = Honker
  strings:
    $s1 = "smsniff.exe" fullword wide
    $s5 = "SmartSniff" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 267KB and all of them
}