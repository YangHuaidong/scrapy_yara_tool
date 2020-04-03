rule Servantshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-02"
    description = "Detects Servantshell malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://tinyurl.com/jmp7nrs"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $string1 = "SelfDestruction.cpp"
    $string2 = "SvtShell.cpp"
    $string3 = "InitServant"
    $string4 = "DeinitServant"
    $string5 = "CheckDT"
  condition:
    uint16(0) == 0x5a4d and all of them
}