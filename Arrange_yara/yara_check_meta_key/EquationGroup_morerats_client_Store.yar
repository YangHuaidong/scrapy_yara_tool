rule EquationGroup_morerats_client_Store {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "619944358bc0e1faffd652b6af0600de055c5e7f1f1d91a8051ed9adf5a5b465"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[-] Failed to mmap file: %s" fullword ascii
    $s2 = "[-] can not NULL terminate input data" fullword ascii
    $s3 = "Missing argument for `-x'." fullword ascii
    $s4 = "[!] Value has size of 0!" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 60KB and 2 of them )
}