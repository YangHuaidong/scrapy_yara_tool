rule Txt_aspxtag {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
    family = "None"
    hacker = "None"
    hash = "42cb272c02dbd49856816d903833d423d3759948"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
    $s2 = "sw.Write(wget);" fullword ascii
    $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
  condition:
    filesize < 2KB and all of them
}