rule APT_WebShell_Tiny_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-18"
    description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "eval(" ascii wide
  condition:
    ( uint16(0) == 0x3f3c or uint16(0) == 0x253c ) and filesize < 40 and $x1
}