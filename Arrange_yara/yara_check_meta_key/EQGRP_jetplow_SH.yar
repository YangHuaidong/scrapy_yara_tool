rule EQGRP_jetplow_SH {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file jetplow.sh"
    family = "None"
    hacker = "None"
    hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
    $s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
    $s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
    $s4 = "*****             Welcome to JetPlow              *****" fullword ascii
  condition:
    1 of them
}