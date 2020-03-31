rule WebShell_CasuS_1_5 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file CasuS 1.5.php
    family = 5
    hacker = None
    hash = 7eee8882ad9b940407acc0146db018c302696341
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[CasuS]/1.5
    threattype = CasuS
  strings:
    $s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
    $s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
    $s18 = "if (file_exists(\"F:\\\\\")){" fullword
  condition:
    1 of them
}