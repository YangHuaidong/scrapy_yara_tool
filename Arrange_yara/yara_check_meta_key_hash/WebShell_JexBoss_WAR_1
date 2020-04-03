rule WebShell_JexBoss_WAR_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-11-08"
    description = "Detects JexBoss versions in WAR form"
    family = "None"
    hacker = "None"
    hash1 = "6271775ab144ce9bb9138bf054b149b5813d3beb96338993c6de35330f566092"
    hash2 = "6f14a63c3034d3762da8b3ad4592a8209a0c88beebcb9f9bd11b40e879f74eaf"
    judge = "unknown"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "jbossass" fullword ascii
    $ = "jexws.jsp" fullword ascii
    $ = "jexws.jspPK" fullword ascii
    $ = "jexws1.jsp" fullword ascii
    $ = "jexws1.jspPK" fullword ascii
    $ = "jexws2.jsp" fullword ascii
    $ = "jexws2.jspPK" fullword ascii
    $ = "jexws3.jsp" fullword ascii
    $ = "jexws3.jspPK" fullword ascii
    $ = "jexws4.jsp" fullword ascii
    $ = "jexws4.jspPK" fullword ascii
  condition:
    uint16(0) == 0x4b50 and filesize < 4KB and 1 of them
}