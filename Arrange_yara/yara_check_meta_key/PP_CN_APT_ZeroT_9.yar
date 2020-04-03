rule PP_CN_APT_ZeroT_9 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-03"
    description = "Detects malware from the Proofpoint CN APT ZeroT incident"
    family = "None"
    hacker = "None"
    hash1 = "a685cf4dca6a58213e67d041bba637dca9cb3ea6bb9ad3eae3ba85229118bce0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "nflogger.dll" fullword ascii
    $s7 = "Zlh.exe" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}