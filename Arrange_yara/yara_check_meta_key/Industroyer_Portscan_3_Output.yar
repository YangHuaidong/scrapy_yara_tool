rule Industroyer_Portscan_3_Output {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-13"
    description = "Detects Industroyer related custom port scaner output file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/x81cSy"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "WSA library load complite." fullword ascii
    $s2 = "Connection refused" fullword ascii
  condition:
    all of them
}