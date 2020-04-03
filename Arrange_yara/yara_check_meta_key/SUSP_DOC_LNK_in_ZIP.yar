rule SUSP_DOC_LNK_in_ZIP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-07-02"
    description = "Detects suspicious .doc.lnk file in ZIP archive"
    family = "None"
    hacker = "None"
    hash1 = "7ea4f77cac557044e72a8e280372a2abe072f2ad98b5a4fbed4e2229e780173a"
    judge = "black"
    reference = "https://twitter.com/RedDrip7/status/1145877272945025029"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".doc.lnk" fullword ascii
  condition:
    uint16(0) == 0x4b50 and 1 of them
}