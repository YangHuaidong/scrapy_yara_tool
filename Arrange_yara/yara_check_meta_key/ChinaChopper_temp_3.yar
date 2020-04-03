rule ChinaChopper_temp_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file temp.aspx"
    family = "None"
    hacker = "None"
    hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
    $s1 = "\"],\"unsafe\");%>" ascii
  condition:
    uint16(0) == 0x253c and filesize < 150 and all of them
}