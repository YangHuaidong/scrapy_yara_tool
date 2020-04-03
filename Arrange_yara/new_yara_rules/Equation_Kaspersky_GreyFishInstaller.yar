rule Equation_Kaspersky_GreyFishInstaller {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/16"
    description = "Equation Group Malware - Grey Fish"
    family = "None"
    hacker = "None"
    hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/ivt8EW"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "DOGROUND.exe" fullword wide
    $s1 = "Windows Configuration Services" fullword wide
    $s2 = "GetMappedFilenameW" fullword ascii
  condition:
    all of them
}