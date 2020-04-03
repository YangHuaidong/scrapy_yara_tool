rule apt_equation_doublefantasy_genericresource {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2015-02-16"
    reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $mz = "MZ"
    $a1 = { 06 00 42 00 49 00 4e 00 52 00 45 00 53 00 }
    $a2 = "yyyyyyyyyyyyyyyy"
    $a3 = "002"
  condition:
    (($mz at 0) and all of ($a*)) and filesize < 500000
}