rule PP_CN_APT_ZeroT_4 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "a9519d2624a842d2c9060b64bb78ee1c400fea9e43d4436371a67cbf90e611b8"
   strings:
      $s1 = "Mcutil.dll" fullword ascii
      $s2 = "mcut.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}