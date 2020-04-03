rule webshell_webshells_new_Asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file Asp.asp"
    family = "None"
    hacker = "None"
    hash = "32c87744ea404d0ea0debd55915010b7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
    $s2 = "Function MorfiCoder(Code)" fullword
    $s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
  condition:
    1 of them
}