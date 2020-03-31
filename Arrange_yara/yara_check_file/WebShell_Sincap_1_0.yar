rule WebShell_Sincap_1_0 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file Sincap 1.0.php
    family = 0
    hacker = None
    hash = 9b72635ff1410fa40c4e15513ae3a496d54f971c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[Sincap]/1.0
    threattype = Sincap
  strings:
    $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
    $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
    $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
    $s12 = "while (($ekinci=readdir ($sedat))){" fullword
    $s19 = "$deger2= \"$ich[$tampon4]\";" fullword
  condition:
    2 of them
}