rule EQGRP_tunnel_state_reader {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file tunnel_state_reader"
    family = "None"
    hacker = "None"
    hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
    $s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii
  condition:
    1 of them
}