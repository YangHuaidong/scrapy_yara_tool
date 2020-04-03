rule Shell_Asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set Webshells - file Asp.html"
    family = "None"
    hacker = "None"
    hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
    $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
    $s3 = "function Command(cmd, str){" fullword ascii
  condition:
    filesize < 100KB and all of them
}