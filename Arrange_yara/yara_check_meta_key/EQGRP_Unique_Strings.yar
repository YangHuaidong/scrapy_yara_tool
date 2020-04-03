rule EQGRP_Unique_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - Unique strings"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
    $s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"
  condition:
    1 of them
}