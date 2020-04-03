rule Fireball_lancer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-02"
    description = "Detects Fireball malware - file lancer.dll"
    family = "None"
    hacker = "None"
    hash1 = "7d68386554e514f38f98f24e8056c11c0a227602ed179d54ed08f2251dc9ea93"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/4pTkGQ"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\instlsp\\Release\\Lancer.pdb" ascii
    $x2 = "lanceruse.dat" fullword wide
    $s1 = "Lancer.dll" fullword ascii
    $s2 = "RunDll32.exe \"" fullword wide
    $s3 = "Micr.dll" fullword wide
    $s4 = "AG64.dll" fullword wide
    $s5 = "\",Start" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or 3 of ($s*) ) ) or ( 6 of them )
}