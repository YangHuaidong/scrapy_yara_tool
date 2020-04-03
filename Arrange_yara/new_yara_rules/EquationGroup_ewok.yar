rule EquationGroup_ewok {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
    family = "None"
    hacker = "None"
    hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Example: ewok -t target public" fullword ascii
    $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
    $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
    $x4 = "--- ewok version" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 80KB and 1 of them )
}