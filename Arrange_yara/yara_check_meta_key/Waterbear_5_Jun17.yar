rule Waterbear_5_Jun17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects malware from Operation Waterbear"
    family = "None"
    hacker = "None"
    hash1 = "d3678cd9744b3aedeba23a03a178be5b82d5f8059a86f816007789a9dd06dc7d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/L9g9eR"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "ICESWORD" fullword ascii
    $a2 = "klog.dat" fullword ascii
    $s1 = "\\cswbse.dll" fullword ascii
    $s2 = "WIRESHARK" fullword ascii
    $s3 = "default_zz|" fullword ascii
    $s4 = "%c4%u-%.2u-%.2u %.2u:%.2u" fullword ascii
    $s5 = "1111%c%s" fullword ascii
  condition:
    ( uint16(0) == 0x3d53 and filesize < 100KB and ( all of ($a*) or 3 of them ) )
}