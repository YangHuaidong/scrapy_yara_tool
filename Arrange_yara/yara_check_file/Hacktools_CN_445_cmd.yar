rule Hacktools_CN_445_cmd {
   meta:
      description = "Disclosed hacktool set - file cmd.bat"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "17.11.14"
      score = 60
      hash = "69b105a3aec3234819868c1a913772c40c6b727a"
   strings:
      $bat = "@echo off" fullword ascii
      $s0 = "cs.exe %1" fullword ascii
      $s2 = "nc %1 4444" fullword ascii
   condition:
      uint32(0) == 0x68636540 and $bat at 0 and all of ($s*)
}