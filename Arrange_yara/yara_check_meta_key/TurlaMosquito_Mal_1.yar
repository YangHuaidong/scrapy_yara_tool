import "pe"
rule TurlaMosquito_Mal_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-22"
    description = "Detects malware sample from Turla Mosquito report"
    family = "None"
    hacker = "None"
    hash1 = "b295032919143f5b6b3c87ad22bcf8b55ecc9244aa9f6f88fc28f36f5aa2925e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Pipetp" fullword ascii
    $s2 = "EStOpnabn" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and (
    pe.imphash() == "169d4237c79549303cca870592278f42" or
    all of them
}