rule EQGRP_Implants_Gen6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall"
    family = "None"
    hacker = "None"
    hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
    hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
    hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
    hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
    hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
    hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
    hash7 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LP.c:pixSecurity - Improper number of bytes read in Security/Interface Information" fullword ascii
    $s2 = "LP.c:pixSecurity - Not in Session" fullword ascii
    $s3 = "getModInterface__preloadedModules" fullword ascii
    $s4 = "showCommands" fullword ascii
    $s5 = "readModuleInterface" fullword ascii
    $s6 = "Wrapping_Not_Necessary_Or_Wrapping_Ok" fullword ascii
    $s7 = "Get_CMD_List" fullword ascii
    $s8 = "LP_Listen2" fullword ascii
    $s9 = "killCmdList" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 6000KB and all of them )
}