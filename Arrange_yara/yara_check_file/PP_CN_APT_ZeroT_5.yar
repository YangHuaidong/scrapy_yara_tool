rule PP_CN_APT_ZeroT_5 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "74dd52aeac83cc01c348528a9bcb20bbc34622b156f40654153e41817083ba1d"
   strings:
      $x1 = "dbozcb" fullword ascii
      $s1 = "nflogger.dll" fullword ascii
      $s2 = "/svchost.exe" fullword ascii
      $s3 = "1207.htm" fullword ascii
      $s4 = "/1207.htm" fullword ascii
   condition:
      ( uint16(0) == 0x5449 and filesize < 1000KB and 1 of ($x*) and 1 of ($s*) ) or ( all of them )
}