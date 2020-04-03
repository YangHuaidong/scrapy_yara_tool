rule MAL_JRAT_Oct18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-10-11"
    description = "Detects JRAT malware"
    family = "None"
    hacker = "None"
    hash1 = "ce190c37a6fdb2632f4bc5ea0bb613b3fbe697d04e68e126b41910a6831d3411"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "/JRat.class" ascii
  condition:
    uint16(0) == 0x4b50 and filesize < 700KB and 1 of them
}