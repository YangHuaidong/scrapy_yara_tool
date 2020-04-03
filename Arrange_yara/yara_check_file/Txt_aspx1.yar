rule Txt_aspx1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
        $s1 = "],\"unsafe\");%>" fullword ascii
    condition:
        filesize < 150 and all of them
}