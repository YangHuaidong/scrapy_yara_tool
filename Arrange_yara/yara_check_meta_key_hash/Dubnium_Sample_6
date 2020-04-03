rule Dubnium_Sample_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-10"
    description = "Detects sample mentioned in the Dubnium Report"
    family = "None"
    hacker = "None"
    hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
    hash2 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
    hash3 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/AW9Cuu"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&()`~-_=+[{]{;',." fullword ascii
    $s2 = "e_$0[bW\\RZY\\jb\\ZY[nimiRc[jRZ]" fullword ascii
    $s3 = "f_RIdJ0W9RFb[$Fbc9[k_?Wn" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}