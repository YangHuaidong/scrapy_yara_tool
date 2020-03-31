rule Txt_hello {
  meta:
    author = Spider
    comment = None
    date = 2015-06-14
    description = Chinese Hacktool Set - Webshells - file hello.txt
    family = None
    hacker = None
    hash = 697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Txt[hello
    threattype = hello.yar
  strings:
    $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
    $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
    $s2 = "myProcess.Start()" fullword ascii
    $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
  condition:
    filesize < 25KB and all of them
}