rule GhostDragon_Gh0stRAT_Sample3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-23"
    description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
    family = "None"
    hacker = "None"
    hash1 = "1be9c68b31247357328596a388010c9cfffadcb6e9841fb22de8b0dc2d161c42"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.cylance.com/the-ghost-dragon"
    threatname = "None"
    threattype = "None"
  strings:
    $op1 = { 44 24 15 65 88 54 24 16 c6 44 24 }
    $op2 = { 44 24 1b 43 c6 44 24 1c 75 88 54 24 1e }
    $op3 = { 1e 79 c6 44 24 1f 43 c6 44 24 20 75 88 54 24 22 }
  condition:
    all of them
}