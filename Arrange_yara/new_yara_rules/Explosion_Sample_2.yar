rule Explosion_Sample_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/03"
    description = "Explosion/Explosive Malware - Volatile Cedar APT"
    family = "None"
    hacker = "None"
    hash = "62fe6e9e395f70dd632c70d5d154a16ff38dcd29"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/5vYaNb"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "serverhelp.dll" fullword wide
    $s1 = "Windows Help DLL" fullword wide
    $s5 = "SetWinHoK" fullword ascii
  condition:
    all of them and
    uint16(0) == 0x5A4D
}