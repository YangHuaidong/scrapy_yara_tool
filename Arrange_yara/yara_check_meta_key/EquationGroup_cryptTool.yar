rule EquationGroup_cryptTool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
    family = "None"
    hacker = "None"
    hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "The encryption key is " fullword ascii
    $s2 = "___tempFile2.out" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}