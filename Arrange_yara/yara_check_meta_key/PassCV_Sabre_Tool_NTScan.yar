rule PassCV_Sabre_Tool_NTScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-10-20"
    description = "PassCV Malware mentioned in Cylance Report"
    family = "None"
    hacker = "None"
    hash1 = "0f290612b26349a551a148304a0bd3b0d0651e9563425d7c362f30bd492d8665"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "NTscan.EXE" fullword wide
    $x2 = "NTscan Microsoft " fullword wide
    $s1 = "admin$" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}