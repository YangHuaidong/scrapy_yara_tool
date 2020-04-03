rule EQGRP_BananaAid {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BananaAid"
    family = "None"
    hacker = "None"
    hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
    $x2 = "scp BGLEE-" ascii
    $x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
    $x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
  condition:
    1 of them
}