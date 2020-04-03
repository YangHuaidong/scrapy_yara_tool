rule Fireball_regkey {
   meta:
      description = "Detects Fireball malware - file regkey.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "fff2818caa9040486a634896f329b8aebaec9121bdf9982841f0646763a1686b"
   strings:
      $s1 = "\\WinMain\\Release\\WinMain.pdb" fullword ascii
      $s2 = "ScreenShot" fullword wide
      $s3 = "WINMAIN" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}