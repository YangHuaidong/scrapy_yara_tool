rule Txt_aspx1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
    family = "None"
    hacker = "None"
    hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
    $s1 = "],\"unsafe\");%>" fullword ascii
  condition:
    filesize < 150 and all of them
}