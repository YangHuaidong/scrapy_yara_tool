rule WebShell__PH_Vayv_PHVayv_PH_Vayv {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
    family = "None"
    hacker = "None"
    hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
    hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
    hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
    $s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {" fullword
    $s17 = "name=\"duzenx2\" value=\"Klas" fullword
  condition:
    2 of them
}