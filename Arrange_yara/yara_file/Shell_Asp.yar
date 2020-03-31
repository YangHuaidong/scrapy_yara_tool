rule Shell_Asp {
    meta:
        description = "Chinese Hacktool Set Webshells - file Asp.html"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "function Command(cmd, str){" fullword ascii
    condition:
        filesize < 100KB and all of them
}