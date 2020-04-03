rule HKTL_PowerKatz_Feb19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-18"
    description = "Detetcs a tool used in the Australian Parliament House network compromise"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Powerkatz32" ascii wide fullword
    $x2 = "Powerkatz64" ascii wide
    $s1 = "GetData: not found taskName" fullword ascii wide
    $s2 = "GetRes Ex:" fullword ascii wide
  condition:
    1 of ($x*) and 1 of ($s*)
}