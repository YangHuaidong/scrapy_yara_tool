rule TurlaMosquito_Mal_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-22"
    description = "Detects malware sample from Turla Mosquito report"
    family = "None"
    hacker = "None"
    hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "/scripts/m/query.php?id=" fullword wide
    $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
    $a3 = "GetUserNameW fails" fullword wide
    $s1 = "QVSWQQ" fullword ascii
    $s2 = "SRRRQP" fullword ascii
    $s3 = "QSVVQQ" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and (
    2 of ($a*) or
    4 of them
}