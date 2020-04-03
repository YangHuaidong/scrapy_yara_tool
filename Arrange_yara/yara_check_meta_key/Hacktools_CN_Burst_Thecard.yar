rule Hacktools_CN_Burst_Thecard {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file Thecard.bat"
    family = "None"
    hacker = "None"
    hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
    $s1 = "Http://www.coffeewl.com" fullword ascii
    $s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
    $s3 = "for /L %%a in (" fullword ascii
    $s4 = "MODE con: COLS=42 lines=5" fullword ascii
  condition:
    all of them
}