rule APT_FIN7_MalDoc_Aug18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-01"
    description = "Detects malicious Doc from FIN7 campaign"
    family = "None"
    hacker = "None"
    hash1 = "9c12591c850a2d5355be0ed9b3891ccb3f42e37eaf979ae545f2f008b5d124d6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<photoshop:LayerText>If this document was downloaded from your email, please click  \"Enable editing\" from the yellow bar above" ascii
  condition:
    filesize < 800KB and 1 of them
}