rule Ysoserial_Payload_MozillaRhino1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-04"
    description = "Ysoserial Payloads - file MozillaRhino1.bin"
    family = "None"
    hacker = "None"
    hash1 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/frohoff/ysoserial"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "ysoserial.payloads" fullword ascii
  condition:
    ( uint16(0) == 0xedac and filesize < 40KB and all of them )
}