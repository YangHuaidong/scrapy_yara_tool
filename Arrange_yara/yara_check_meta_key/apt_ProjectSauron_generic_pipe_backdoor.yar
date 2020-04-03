rule apt_ProjectSauron_generic_pipe_backdoor {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect ProjectSauron generic pipe backdoors"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://securelist.com/blog/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a = { C7 [2-3] 32 32 32 32 E8 }
    $b = { 42 12 67 6b }
    $c = { 25 31 5f 73 }
    $d = "rand"
    $e = "WS2_32"
  condition:
    uint16(0) == 0x5A4D and
    (all of them) and
    filesize < 400000
}