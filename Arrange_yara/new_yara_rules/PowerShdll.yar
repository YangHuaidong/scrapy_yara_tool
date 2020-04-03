rule PowerShdll {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-03"
    description = "Detects hack tool PowerShdll"
    family = "None"
    hacker = "None"
    hash1 = "4d33bc7cfa79d7eefc5f7a99f1b052afdb84895a411d7c30045498fd4303898a"
    hash2 = "f999db9cc3a0719c19f35f0e760f4ce3377b31b756d8cd91bb8270acecd7be7d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/p3nt4/PowerShdll"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "rundll32 PowerShdll,main -f <path>" fullword wide
    $x2 = "\\PowerShdll.dll" fullword ascii
    $x3 = "rundll32 PowerShdll,main <script>" fullword wide
  condition:
    1 of them
}