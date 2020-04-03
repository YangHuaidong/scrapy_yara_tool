rule PP_CN_APT_ZeroT_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-03"
    description = "Detects malware from the Proofpoint CN APT ZeroT incident"
    family = "None"
    hacker = "None"
    hash1 = "09061c603a32ac99b664f7434febfc8c1f9fd7b6469be289bb130a635a6c47c0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "suprise.exe" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}