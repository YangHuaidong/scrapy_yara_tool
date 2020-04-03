rule Mal_Dropper_httpEXE_from_CAB {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-05-25"
    description = "Detects a dropper from a CAB file mentioned in the article"
    family = "None"
    hacker = "None"
    hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/13Wgy1"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "029.Hdl" fullword ascii
    $s2 = "http.exe" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) )
}