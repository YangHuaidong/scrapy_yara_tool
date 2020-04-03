rule Sword1_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Sword1.5.exe"
    family = "None"
    hacker = "None"
    hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "http://www.ip138.com/ip2city.asp" fullword wide
    $s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
    $s6 = "ListBox_Command" fullword wide
    $s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
    $s18 = "\\Set.ini" fullword wide
    $s19 = "OpenFileDialog1" fullword wide
    $s20 = " (*.txt)|*.txt" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}