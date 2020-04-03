rule Casper_EXE_Dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/05"
    description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
    family = "None"
    hacker = "None"
    hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/VRJNLo"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<Command>" fullword ascii
    $s1 = "</Command>" fullword ascii
    $s2 = "\" /d \"" fullword ascii
    $s4 = "'%s' %s" fullword ascii
    $s5 = "nKERNEL32.DLL" fullword wide
    $s6 = "@ReturnValue" fullword wide
    $s7 = "ID: 0x%x" fullword ascii
    $s8 = "Name: %S" fullword ascii
  condition:
    7 of them
}