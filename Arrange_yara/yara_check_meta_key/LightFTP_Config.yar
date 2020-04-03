rule LightFTP_Config {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-14"
    description = "Detects a light FTP server - config file"
    family = "None"
    hacker = "None"
    hash = "ce9821213538d39775af4a48550eefa3908323c5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/hfiref0x/LightFTP"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "maxusers=" wide
    $s6 = "[ftpconfig]" fullword wide
    $s8 = "accs=readonly" fullword wide
    $s9 = "[anonymous]" fullword wide
    $s10 = "accs=" fullword wide
    $s11 = "pswd=" fullword wide
  condition:
    uint16(0) == 0xfeff and filesize < 1KB and all of them
}