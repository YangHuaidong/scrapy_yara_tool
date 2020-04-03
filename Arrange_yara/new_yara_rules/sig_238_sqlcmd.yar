rule sig_238_sqlcmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
    family = "None"
    hacker = "None"
    hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Permission denial to EXEC command.:(" fullword ascii
    $s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
    $s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
    $s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
    $s6 = "SqlCmd2.exe Inside Edition." fullword ascii
    $s7 = "Http://www.patching.net  2000/12/14" fullword ascii
    $s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii
  condition:
    4 of them
}