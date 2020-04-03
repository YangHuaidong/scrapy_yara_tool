rule EquationGroup_ys_ratload {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
    family = "None"
    hacker = "None"
    hash1 = "a340e5b5cfd41076bd4d6ad89d7157eeac264db97a9dddaae15d935937f10d75"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
    $x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
    $x3 = "CALLBACK_PORT=32177" fullword ascii
  condition:
    ( uint16(0) == 0x2123 and filesize < 3KB and 1 of them )
}