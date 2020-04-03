rule Fidelis_Advisory_cedt370 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-09"
    description = "Detects a string found in memory of malware cedt370r(3).exe"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/ZjJyti"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "PO.exe" ascii fullword
    $s1 = "Important.exe" ascii fullword
    $s2 = "&username=" ascii fullword
    $s3 = "Browsers.txt" ascii fullword
  condition:
    all of them
}