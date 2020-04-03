rule EQGRP_userscript {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file userscript.FW"
    family = "None"
    hacker = "None"
    hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii
  condition:
    1 of them
}