rule EquationGroup_slugger2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
    family = "None"
    hacker = "None"
    hash1 = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
    $x2 = "command must be less than 61 chars" fullword ascii
    $s1 = "__rw_read_waiting" fullword ascii
    $s2 = "completed.1" fullword ascii
    $s3 = "__mutexkind" fullword ascii
    $s4 = "__rw_pshared" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ($x*) ) ) or ( all of them )
}