rule CN_Honker_Baidu_Extractor_Ver1_0 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file Baidu_Extractor_Ver1.0.exe
    family = Extractor
    hacker = None
    hash = 1899f979360e96245d31082e7e96ccedbdbe1413
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/Baidu.Extractor.Ver1.0
    threattype = Honker
  strings:
    $s3 = "\\Users\\Admin" fullword wide /* PEStudio Blacklist: strings */
    $s11 = "soso.com" fullword wide
    $s12 = "baidu.com" fullword wide
    $s19 = "cmd /c ping " fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and all of them
}