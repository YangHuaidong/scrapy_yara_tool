rule TeleBots_Win64_Spy_KeyLogger_G {
   meta:
      description = "Detects TeleBots malware - Win64 Spy KeyLogger G"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "e3f134ae88f05463c4707a80f956a689fba7066bb5357f6d45cba312ad0db68e"
   strings:
      $s1 = "C:\\WRK\\GHook\\gHook\\x64\\Debug\\gHookx64.pdb" fullword ascii
      $s2 = "Install hooks error!" fullword wide
      $s4 = "%ls%d.~tmp" fullword wide
      $s5 = "[*]Window PID > %d: " fullword wide
      $s6 = "Install hooks ok!" fullword wide
      $s7 = "[!]Clipboard paste" fullword wide
      $s9 = "[*] IMAGE : %ls" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them ) or ( 3 of them )
}