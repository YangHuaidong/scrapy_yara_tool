rule Txt_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file asp.txt"
    family = "None"
    hacker = "None"
    hash = "a63549f749f4d9d0861825764e042e299e06a705"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
    $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
  condition:
    uint16(0) == 0x253c and filesize < 100KB and all of them
}