rule EQGRP_BUSURPER_2211_724 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
    family = "None"
    hacker = "None"
    hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".got_loader" fullword ascii
    $s2 = "_start_text" fullword ascii
    $s3 = "IMPLANT" fullword ascii
    $s4 = "KEEPGOING" fullword ascii
    $s5 = "upgrade_implant" fullword ascii
  condition:
    all of them
}