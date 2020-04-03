rule PSAttack_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-03-09"
    description = "PSAttack - Powershell attack tool - file PSAttack.exe"
    family = "None"
    hacker = "None"
    hash = "ad05d75640c850ee7eeee26422ba4f157be10a4e2d6dc6eaa19497d64cf23715"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/gdssecurity/PSAttack/releases/"
    score = 100
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Release\\PSAttack.pdb" fullword
    $s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
    $s2 = "PSAttack.Modules." ascii
    $s3 = "PSAttack.PSAttackProcessing" fullword ascii
    $s4 = "PSAttack.Modules.key.txt" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and ( $x1 or 2 of ($s*) ) ) or 3 of them
}