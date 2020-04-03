rule EquationGroup_evolvingstrategy_1_0_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file evolvingstrategy.1.0.1.1"
    family = "None"
    hacker = "None"
    hash1 = "fe70e16715992cc86bbef3e71240f55c7d73815b4247d7e866c845b970233c1b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "chown root sh; chmod 4777 sh;" fullword ascii
    $s2 = "cp /bin/sh .;chown root sh;" fullword ascii
    $l1 = "echo clean up when elevated:" fullword ascii
    $x1 = "EXE=$DIR/sbin/ey_vrupdate" fullword ascii
  condition:
    ( filesize < 4KB and 1 of them )
}