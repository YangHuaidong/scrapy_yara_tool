rule SUSP_Microsoft_Copyright_String_Anomaly_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-11"
    description = "Detects Floxif Malware"
    family = "None"
    hacker = "None"
    hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}