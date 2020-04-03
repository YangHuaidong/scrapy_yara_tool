rule WebShell_php_webshells_kral {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file kral.php"
    family = "None"
    hacker = "None"
    hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$adres=gethostbyname($ip);" fullword
    $s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);" fullword
    $s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";" fullword
    $s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';" fullword
    $s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
    $s20 = "<p><strong>Server listeleyici</strong><br />" fullword
  condition:
    2 of them
}