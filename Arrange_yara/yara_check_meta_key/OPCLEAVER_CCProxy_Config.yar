rule OPCLEAVER_CCProxy_Config {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "CCProxy config known from Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "UserName=User-001" fullword ascii
    $s2 = "Web=1" fullword ascii
    $s3 = "Mail=1" fullword ascii
    $s4 = "FTP=0" fullword ascii
    $x1 = "IPAddressLow=78.109.194.114" fullword ascii
  condition:
    all of ($s*) or $x1
}