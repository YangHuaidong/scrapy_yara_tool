rule EquationGroup_orleans_stride_sunos5_9_v_2_4_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "6a30efb87b28e1a136a66c7708178c27d63a4a76c9c839b2fc43853158cb55ff"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "_lib_version" fullword ascii
    $s2 = ",%02d%03d" fullword ascii
    $s3 = "TRANSIT" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}