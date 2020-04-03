rule Ajan_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Ajan.asp.txt"
    family = "None"
    hacker = "None"
    hash = "b6f468252407efc2318639da22b08af0"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "c:\\downloaded.zip"
    $s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
    $s3 = "http://www35.websamba.com/cybervurgun/"
  condition:
    1 of them
}