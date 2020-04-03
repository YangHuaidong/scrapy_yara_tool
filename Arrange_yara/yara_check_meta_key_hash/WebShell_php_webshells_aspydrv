rule WebShell_php_webshells_aspydrv {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file aspydrv.php"
    family = "None"
    hacker = "None"
    hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
    $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
    $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
    $s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
    $s20 = "' ---Copy Too Folder routine Start" fullword
  condition:
    3 of them
}