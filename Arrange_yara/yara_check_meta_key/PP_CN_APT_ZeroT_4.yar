rule PP_CN_APT_ZeroT_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-03"
    description = "Detects malware from the Proofpoint CN APT ZeroT incident"
    family = "None"
    hacker = "None"
    hash1 = "a9519d2624a842d2c9060b64bb78ee1c400fea9e43d4436371a67cbf90e611b8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Mcutil.dll" fullword ascii
    $s2 = "mcut.exe" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}