rule EquationGroup_toast_v3_2_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file toast_v3.2.0.1-linux"
    family = "None"
    hacker = "None"
    hash1 = "2ce2d16d24069dc29cf1464819a9dc6deed38d1e5ffc86d175b06ddb691b648b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
    $s5 = "Roasting ->%s<- at ->%d:%d<-" fullword ascii
    $s6 = "rbnoil -Roasting ->" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}