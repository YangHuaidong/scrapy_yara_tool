rule EquationGroup_electricslide {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
    family = "None"
    hacker = "None"
    hash1 = "d27814b725568fa73641e86fa51850a17e54905c045b8b31a9a5b6d2bdc6f014"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
    $x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
    $x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
    $x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}