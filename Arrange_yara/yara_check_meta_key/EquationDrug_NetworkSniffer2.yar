rule EquationDrug_NetworkSniffer2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Network Sniffer - tdip.sys"
    family = "None"
    hacker = "None"
    hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"
    judge = "black"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
    $s1 = "IP Transport Driver" fullword wide
    $s2 = "tdip.sys" fullword wide
    $s3 = "sys\\tdip.dbg" fullword ascii
    $s4 = "dip.sys" fullword ascii
    $s5 = "\\Device\\%ws_%ws" fullword wide
    $s6 = "\\DosDevices\\%ws" fullword wide
    $s7 = "\\Device\\%ws" fullword wide
  condition:
    all of them
}