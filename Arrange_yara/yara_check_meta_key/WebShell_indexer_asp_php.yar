rule WebShell_indexer_asp_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
    family = "None"
    hacker = "None"
    hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
    $s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
    $s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
    $s4 = "<form action=\"?oku\" method=\"post\">" fullword
    $s7 = "var message=\"SaNaLTeRoR - " fullword
    $s8 = "nDexEr - Reader\"" fullword
  condition:
    3 of them
}