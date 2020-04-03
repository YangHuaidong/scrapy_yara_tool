rule CN_Honker_T00ls_Lpk_Sethc_v3_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v3.0.exe"
    family = "None"
    hacker = "None"
    hash = "fa47c4affbac01ba5606c4862fdb77233c1ef656"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://127.0.0.1/1.exe" fullword wide /* PEStudio Blacklist: strings */
    $s2 = ":Rices  Forum:T00Ls.Net  [4 Fucker Te@m]" fullword wide
    $s3 = "SkinH_EL.dll" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}