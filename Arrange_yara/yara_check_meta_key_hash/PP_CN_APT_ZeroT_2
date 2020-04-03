rule PP_CN_APT_ZeroT_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-03"
    description = "Detects malware from the Proofpoint CN APT ZeroT incident"
    family = "None"
    hacker = "None"
    hash1 = "74eb592ef7f5967b14794acdc916686e061a43169f06e5be4dca70811b9815df"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "NO2-2016101902.exe" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}