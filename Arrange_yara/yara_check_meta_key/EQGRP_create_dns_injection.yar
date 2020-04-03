rule EQGRP_create_dns_injection {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file create_dns_injection.py"
    family = "None"
    hacker = "None"
    hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Name:   A hostname: 'host.network.com', a decimal numeric offset within" fullword ascii
    $s2 = "-a www.badguy.net,CNAME,1800,host.badguy.net \\\\" fullword ascii
  condition:
    1 of them
}