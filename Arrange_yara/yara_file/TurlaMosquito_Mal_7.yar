rule TurlaMosquito_Mal_7 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "e7fd14ca45818044690ca67f201cc8cfb916ccc941a105927fc4c932c72b425d"
   strings:
      $x1 = "Logger32.dll" fullword ascii
      $s6 = "lManager::Execute : CPalExceptio" fullword wide
      $s19 = "CCommandSender::operator(" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
        pe.imphash() == "073235ae6dfbb1bf5db68a039a7b7726" or
        3 of them
      )
}