rule sig_238_gina {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file gina.reg"
    family = "None"
    hacker = "None"
    hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\"gina\"=\"gina.dll\"" fullword ascii
    $s1 = "REGEDIT4" fullword ascii
    $s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii
  condition:
    all of them
}