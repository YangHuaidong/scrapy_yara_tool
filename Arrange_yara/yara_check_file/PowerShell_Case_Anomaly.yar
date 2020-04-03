rule PowerShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated PowerShell hacktools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
      date = "2017-08-11"
      score = 70
   strings:
      $s1 = "powershell" fullword nocase ascii wide
      $sr1 = /(powershell|Powershell|PowerShell|POWERSHELL|powerShell)/ fullword ascii wide
      $sn1 = "powershell" fullword ascii wide
      $sn2 = "Powershell" fullword ascii wide
      $sn3 = "PowerShell" fullword ascii wide
      $sn4 = "POWERSHELL" fullword ascii wide
      $sn5 = "powerShell" fullword ascii wide
      $a1 = "wershell -e " nocase wide ascii
      $an1 = "wershell -e " wide ascii
      $an2 = "werShell -e " wide ascii
      $k1 = "-noprofile" fullword nocase ascii wide
      $kn1 = "-noprofile" ascii wide
      $kn2 = "-NoProfile" ascii wide
      $kn3 = "-noProfile" ascii wide
      $kn4 = "-NOPROFILE" ascii wide
      $kn5 = "-Noprofile" ascii wide
      $fp1 = "Microsoft Code Signing" ascii fullword
      $fp2 = "Microsoft Corporation" ascii
   condition:
      filesize < 800KB and (
         ( #s1 < 3 and #sr1 > 0 and #s1 > #sr1 ) or
         ( $s1 and not 1 of ($sn*) ) or
         ( $a1 and not 1 of ($an*) ) or
         ( $k1 and not 1 of ($kn*) )
      ) and not 1 of ($fp*)
}