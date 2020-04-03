rule winlogon_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/16"
    description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file winlogon.exe"
    family = "None"
    hacker = "None"
    hash = "af210c8748d77c2ff93966299d4cd49a8c722ef6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "AuthzAccessCheck failed" fullword
    $s2 = "Windows Logon Application" fullword wide
  condition:
    filename == "winlogon.exe"
    and not 1 of ($s*)
    and uint16(0) == 0x5a4d
    and not WINDOWS_UPDATE_BDC
    and not filepath contains "Malwarebytes"
}