import "pe"
rule MAL_Floxif_Generic {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-11"
    description = "Detects Floxif Malware"
    family = "None"
    hacker = "None"
    hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 80
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and (
    pe.imphash() == "2f4ddcfebbcad3bacadc879747151f6f" or
    pe.exports("FloodFix") or pe.exports("FloodFix2")
}