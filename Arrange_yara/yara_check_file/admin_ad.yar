rule admin_ad {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file admin-ad.asp
    family = None
    hacker = None
    hash = e6819b8f8ff2f1073f7d46a0b192f43b
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = admin[ad
    threattype = ad.yar
  strings:
    $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
    $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
  condition:
    all of them
}