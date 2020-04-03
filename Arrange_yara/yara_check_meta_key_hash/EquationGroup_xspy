rule EquationGroup_xspy {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
    family = "None"
    hacker = "None"
    hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}