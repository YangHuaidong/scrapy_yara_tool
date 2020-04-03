rule Hacktools_CN_Burst_pass {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file pass.txt"
    family = "None"
    hacker = "None"
    hash = "55a05cf93dbd274355d798534be471dff26803f9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "123456.com" fullword ascii
    $s1 = "123123.com" fullword ascii
    $s2 = "360.com" fullword ascii
    $s3 = "123.com" fullword ascii
    $s4 = "juso.com" fullword ascii
    $s5 = "sina.com" fullword ascii
    $s7 = "changeme" fullword ascii
    $s8 = "master" fullword ascii
    $s9 = "google.com" fullword ascii
    $s10 = "chinanet" fullword ascii
    $s12 = "lionking" fullword ascii
  condition:
    all of them
}