rule IsmDoor_Jul17_A2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-01"
    description = "Detects IsmDoor Malware"
    family = "None"
    hacker = "None"
    hash1 = "be72c89efef5e59c4f815d2fce0da5a6fac8c90b86ee0e424868d4ae5e550a59"
    hash2 = "ea1be14eb474c9f70e498c764aaafc8b34173c80cac9a8b89156e9390bd87ba8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/Voulnet/status/892104753295110145"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "powershell -exec bypass -file \"" fullword ascii
    $s2 = "PAQlFcaWUaFkVICEx2CkNCUUpGcA" ascii
    $s3 = "\\Documents" fullword ascii
    $s4 = "\\Libraries" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}