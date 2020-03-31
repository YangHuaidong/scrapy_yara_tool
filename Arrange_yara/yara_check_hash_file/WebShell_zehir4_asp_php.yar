rule WebShell_zehir4_asp_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file zehir4.asp.php.txt
    family = php
    hacker = None
    hash = 1d9b78b5b14b821139541cc0deb4cbbd994ce157
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[zehir4]/asp.php
    threattype = zehir4
  strings:
    $s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
    $s11 = "frames.byZehir.document.execCommand("
    $s15 = "frames.byZehir.document.execCommand(co"
  condition:
    2 of them
}