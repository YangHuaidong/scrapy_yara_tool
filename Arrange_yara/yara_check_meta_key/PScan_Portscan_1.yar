rule PScan_Portscan_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PScan - Port Scanner"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $a = "00050;0F0M0X0a0v0}0"
    $b = "vwgvwgvP76"
    $c = "Pr0PhOFyP"
  condition:
    all of them
}