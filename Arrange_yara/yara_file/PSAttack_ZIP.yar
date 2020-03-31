rule PSAttack_ZIP {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.zip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09"
      score = 100
      hash = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2"
   strings:
      $s0 = "PSAttack.exe" fullword ascii
   condition:
      uint16(0) == 0x4b50 and all of them
}