rule EQGRP_extrabacon {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
    family = "None"
    hacker = "None"
    hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "To disable password checking on target:" fullword ascii
    $x2 = "[-] target is running" fullword ascii
    $x3 = "[-] problem importing version-specific shellcode from" fullword ascii
    $x4 = "[+] importing version-specific shellcode" fullword ascii
    $s5 = "[-] unsupported target version, abort" fullword ascii
  condition:
    1 of them
}