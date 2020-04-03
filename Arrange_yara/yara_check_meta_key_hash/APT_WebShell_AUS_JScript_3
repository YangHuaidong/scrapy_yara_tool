rule APT_WebShell_AUS_JScript_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-18"
    description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
    family = "None"
    hacker = "None"
    hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
    judge = "unknown"
    reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
    $s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii
  condition:
    uint16(0) == 0x6568 and filesize < 1KB and all of them
}