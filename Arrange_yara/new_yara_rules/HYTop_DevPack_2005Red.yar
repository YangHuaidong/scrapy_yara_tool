rule HYTop_DevPack_2005Red {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005Red.asp"
    family = "None"
    hacker = "None"
    hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "scrollbar-darkshadow-color:#FF9DBB;"
    $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
    $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
  condition:
    all of them
}