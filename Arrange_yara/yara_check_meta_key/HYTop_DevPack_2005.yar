rule HYTop_DevPack_2005 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005.asp"
    family = "None"
    hacker = "None"
    hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
    $s8 = "scrollbar-darkshadow-color:#9C9CD3;"
    $s9 = "scrollbar-face-color:#E4E4F3;"
  condition:
    all of them
}