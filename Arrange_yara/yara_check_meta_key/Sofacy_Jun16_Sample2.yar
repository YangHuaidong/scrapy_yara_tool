rule Sofacy_Jun16_Sample2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-14"
    description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
    family = "None"
    hacker = "None"
    hash1 = "57d230ddaf92e2d0504e5bb12abf52062114fb8980c5ecc413116b1d6ffedf1b"
    hash2 = "69940a20ab9abb31a03fcefe6de92a16ed474bbdff3288498851afc12a834261"
    hash3 = "aeeab3272a2ed2157ebf67f74c00fafc787a2b9bbaa17a03be1e23d4cb273632"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/mzAa97"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "DGMNOEP" fullword ascii
    $x2 = "/%s%s%s/?%s=" fullword ascii
    $s1 = "Control Panel\\Dehttps=https://%snetwork.proxy.ht2" fullword ascii
    $s2 = "http=http://%s:%Control Panel\\Denetwork.proxy.ht&ol1mS9" fullword ascii
    $s3 = "svchost.dll" fullword wide
    $s4 = "clconfig.dll" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and ( all of ($x*) ) ) or ( 3 of them )
}