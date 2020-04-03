rule EquationDrug_NetworkSniffer1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
    family = "None"
    hacker = "None"
    hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"
    judge = "black"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
    $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
    $s3 = "sys\\mstcp32.dbg" fullword ascii
    $s7 = "mstcp32.sys" fullword wide
    $s8 = "p32.sys" fullword ascii
    $s9 = "\\Device\\%ws_%ws" fullword wide
    $s10 = "\\DosDevices\\%ws" fullword wide
    $s11 = "\\Device\\%ws" fullword wide
  condition:
    all of them
}