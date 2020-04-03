rule EquationGroup__magicjack_v1_1_0_0_client {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- from files magicjack_v1.1.0.0_client-1.1.0.0.py"
    family = "None"
    hacker = "None"
    hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "temp = ((left >> 1) ^ right) & 0x55555555" fullword ascii
    $s2 = "right ^= (temp <<  16) & 0xffffffff" fullword ascii
    $s3 = "tempresult = \"\"" fullword ascii
    $s4 = "num = self.bytes2long(data)" fullword ascii
  condition:
    ( uint16(0) == 0x2123 and filesize < 80KB and 3 of them ) or ( all of them )
}