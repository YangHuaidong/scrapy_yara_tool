rule EquationGroup_sambal {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file sambal"
    family = "None"
    hacker = "None"
    hash1 = "2abf4bbe4debd619b99cb944298f43312db0947217437e6b71b9ea6e9a1a4fec"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "+ Bruteforce mode." fullword ascii
    $s3 = "+ Host is not running samba!" fullword ascii
    $s4 = "+ connecting back to: [%d.%d.%d.%d:45295]" fullword ascii
    $s5 = "+ Exploit failed, try -b to bruteforce." fullword ascii
    $s7 = "Usage: %s [-bBcCdfprsStv] [host]" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}