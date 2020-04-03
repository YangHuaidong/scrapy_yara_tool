rule Explosive_UA {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/03"
    description = "Explosive Malware Embedded User Agent - Volatile Cedar APT http://goo.gl/HQRCdw"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/HQRCdw"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CLR 2.0.50727)" fullword
  condition:
    $x1 and
    uint16(0) == 0x5A4D
}