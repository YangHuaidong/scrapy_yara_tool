rule DropBear_SSH_Server {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-03"
    description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
    family = "None"
    hacker = "None"
    hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
    $s2 = "Badly formatted command= authorized_keys option" fullword ascii
    $s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
    $s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
    $s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}