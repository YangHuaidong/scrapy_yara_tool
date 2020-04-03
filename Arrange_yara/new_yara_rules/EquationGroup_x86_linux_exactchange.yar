rule EquationGroup_x86_linux_exactchange {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
    hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
    $x2 = "[+] kernel stack size is %d" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 1000KB and 1 of them )
}