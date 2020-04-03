rule unknown2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file unknown2.exe"
    family = "None"
    hacker = "None"
    hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
    $s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
    $s3 = "http://www.md5.com.cn" fullword wide
    $s4 = "1.5.exe" fullword wide
    $s5 = "\\Set.ini" fullword wide
    $s6 = "OpenFileDialog1" fullword wide
    $s7 = " (*.txt)|*.txt" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}