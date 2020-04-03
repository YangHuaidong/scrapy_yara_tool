rule Empire_Invoke_EgressCheck {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file Invoke-EgressCheck.ps1"
    family = "None"
    hacker = "None"
    hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
  condition:
    ( uint16(0) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}