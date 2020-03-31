rule Webshell_AcidPoison {
  meta:
    author = Spider
    comment = None
    date = 2016-01-11
    description = Detects Poison Sh3ll - Webshell
    family = None
    hacker = None
    hash1 = 7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549
    hash10 = ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f
    hash2 = 7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549
    hash3 = d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc
    hash4 = d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc
    hash5 = 65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791
    hash6 = 65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791
    hash7 = be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5
    hash8 = be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5
    hash9 = ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/nikicat/web-malware-collection
    score = 70
    threatname = Webshell[AcidPoison
    threattype = AcidPoison.yar
  strings:
    $s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" fullword ascii
  condition:
    filesize < 550KB and all of them
}