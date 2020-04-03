rule SUSP_Just_EICAR {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-03-24"
    description = "Just an EICAR test file - this is boring but users asked for it"
    family = "None"
    hacker = "None"
    hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    judge = "unknown"
    reference = "http://2016.eicar.org/85-0-Download.html"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
  condition:
    uint16(0) == 0x3558 and filesize < 70 and $s1 at 0
}