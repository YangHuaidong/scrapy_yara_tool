import "pe"
rule TurlaMosquito_Mal_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-22"
    description = "Detects malware sample from Turla Mosquito report"
    family = "None"
    hacker = "None"
    hash1 = "b362b235539b762734a1833c7e6c366c1b46474f05dc17b3a631b3bff95a5eec"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "17b328245e2874a76c2f46f9a92c3bad"
}