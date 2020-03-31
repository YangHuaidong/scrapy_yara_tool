rule PSAttack_ZIP {
  meta:
    author = Spider
    comment = None
    date = 2016-03-09
    description = PSAttack - Powershell attack tool - file PSAttack.zip
    family = None
    hacker = None
    hash = 3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/gdssecurity/PSAttack/releases/
    score = 100
    threatname = PSAttack[ZIP
    threattype = ZIP.yar
  strings:
    $s0 = "PSAttack.exe" fullword ascii
  condition:
    uint16(0) == 0x4b50 and all of them
}