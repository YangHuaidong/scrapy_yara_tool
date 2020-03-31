rule WebShell_php_webshells_spygrup {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file spygrup.php
    family = spygrup
    hacker = None
    hash = 12f9105332f5dc5d6360a26706cd79afa07fe004
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[php]/webshells.spygrup
    threattype = php
  strings:
    $s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
    $s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
    $s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
    $s18 = "By KingDefacer From Spygrup.org>" fullword
  condition:
    3 of them
}