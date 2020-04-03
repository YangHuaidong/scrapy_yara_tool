rule PP_CN_APT_ZeroT_2 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "74eb592ef7f5967b14794acdc916686e061a43169f06e5be4dca70811b9815df"
   strings:
      $s1 = "NO2-2016101902.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}