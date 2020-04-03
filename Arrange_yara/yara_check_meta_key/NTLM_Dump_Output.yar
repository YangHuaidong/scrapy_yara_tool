rule NTLM_Dump_Output {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-10-01"
    description = "NTML Hash Dump output file - John/LC format"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
    $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
  condition:
    1 of them
}