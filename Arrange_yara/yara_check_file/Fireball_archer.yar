rule Fireball_archer {
   meta:
      description = "Detects Fireball malware - file archer.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022"
   strings:
      $x1 = "\\archer_lyl\\Release\\Archer_Input.pdb" fullword ascii
      $s1 = "Archer_Input.dll" fullword ascii
      $s2 = "InstallArcherSvc" fullword ascii
      $s3 = "%s_%08X" fullword wide
      $s4 = "d\\\\.\\PhysicalDrive%d" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and ( $x1 or 3 of them )
}