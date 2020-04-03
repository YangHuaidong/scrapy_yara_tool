rule Hacktools_CN_445_cmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file cmd.bat"
    family = "None"
    hacker = "None"
    hash = "69b105a3aec3234819868c1a913772c40c6b727a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $bat = "@echo off" fullword ascii
    $s0 = "cs.exe %1" fullword ascii
    $s2 = "nc %1 4444" fullword ascii
  condition:
    uint32(0) == 0x68636540 and $bat at 0 and all of ($s*)
}