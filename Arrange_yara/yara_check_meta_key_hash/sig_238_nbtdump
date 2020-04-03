rule sig_238_nbtdump {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
    family = "None"
    hacker = "None"
    hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Creation of results file - \"%s\" failed." fullword ascii
    $s1 = "c:\\>nbtdump remote-machine" fullword ascii
    $s7 = "Cerberus NBTDUMP" fullword ascii
    $s11 = "<CENTER><H1>Cerberus Internet Scanner</H1>" fullword ascii
    $s18 = "<P><H3>Account Information</H3><PRE>" fullword wide
    $s19 = "%s's password is %s</H3>" fullword wide
    $s20 = "%s's password is blank</H3>" fullword wide
  condition:
    5 of them
}