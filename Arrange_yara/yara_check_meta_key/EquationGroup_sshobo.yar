rule EquationGroup_sshobo {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
    family = "None"
    hacker = "None"
    hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
    $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
    $x3 = "~#  - list forwarded connections" fullword ascii
    $x4 = "packet_inject_ignore: block" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 600KB and all of them )
}