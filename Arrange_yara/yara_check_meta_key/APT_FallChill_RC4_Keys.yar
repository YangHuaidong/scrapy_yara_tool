rule APT_FallChill_RC4_Keys {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-21"
    description = "Detects FallChill RC4 keys"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/operation-applejeus/87553/"
    threatname = "None"
    threattype = "None"
  strings:
    /* MOV POS 4BYTE-OF-KEY */
    $cod0 = { c7 ?? ?? da e1 61 ff
    c7 ?? ?? 0c 27 95 87
    c7 ?? ?? 17 57 a4 d6
    c7 ?? ?? ea e3 82 2b }
  condition:
    uint16(0) == 0x5a4d and 1 of them
}