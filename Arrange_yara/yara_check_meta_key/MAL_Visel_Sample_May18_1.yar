import "pe"
rule MAL_Visel_Sample_May18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-04"
    description = "Detects Visel malware sample from Burning Umbrella report"
    family = "None"
    hacker = "None"
    hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://401trg.pw/burning-umbrella/"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "print32.dll" fullword ascii
    $s3 = "c:\\a\\b.txt" fullword ascii
    $s4 = "\\temp\\s%d.dat" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and (
    pe.exports("szFile") or
    2 of them
}