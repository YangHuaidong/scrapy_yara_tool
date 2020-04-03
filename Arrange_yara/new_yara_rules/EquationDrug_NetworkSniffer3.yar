rule EquationDrug_NetworkSniffer3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Network Sniffer - tdip.sys"
    family = "None"
    hacker = "None"
    hash = "14599516381a9646cd978cf962c4f92386371040"
    judge = "unknown"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Corporation. All rights reserved." fullword wide
    $s1 = "IP Transport Driver" fullword wide
    $s2 = "tdip.sys" fullword wide
    $s3 = "tdip.pdb" fullword ascii
  condition:
    all of them
}