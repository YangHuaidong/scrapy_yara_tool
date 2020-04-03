rule Winnti_signing_cert {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-10-10"
    description = "Detects a signing certificate used by the Winnti APT group"
    family = "None"
    hacker = "None"
    hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
    hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Guangzhou YuanLuo Technology Co." ascii
    $s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
    $s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}