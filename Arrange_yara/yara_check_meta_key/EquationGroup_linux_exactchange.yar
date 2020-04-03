rule EquationGroup_linux_exactchange {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
    hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
    hash3 = "39d4f83c7e64f5b89df9851bdba917cf73a3449920a6925b6cd379f2fdec2a8b"
    hash4 = "15e12c1c27304e4a68a268e392be4972f7c6edf3d4d387e5b7d2ed77a5b43c2c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[+] looking for vulnerable socket" fullword ascii
    $x2 = "can't use 32-bit exploit on 64-bit target" fullword ascii
    $x3 = "[+] %s socket ready, exploiting..." fullword ascii
    $x4 = "[!] nothing looks vulnerable, trying everything" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}