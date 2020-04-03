rule MAL_JRAT_Oct18_1 {
   meta:
      description = "Detects JRAT malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-11"
      hash1 = "ce190c37a6fdb2632f4bc5ea0bb613b3fbe697d04e68e126b41910a6831d3411"
   strings:
      $x1 = "/JRat.class" ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and 1 of them
}