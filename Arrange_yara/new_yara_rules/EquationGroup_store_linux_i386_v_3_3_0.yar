rule EquationGroup_store_linux_i386_v_3_3_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[-] Failed to map file: %s" fullword ascii
    $s2 = "[-] can not NULL terminate input data" fullword ascii
    $s3 = "[!] Name has size of 0!" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}