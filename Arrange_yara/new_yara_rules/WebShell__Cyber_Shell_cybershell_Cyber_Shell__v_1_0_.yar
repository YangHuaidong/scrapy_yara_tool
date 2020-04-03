rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_ {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
    family = "None"
    hacker = "None"
    hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
    hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
    hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
    $s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
    $s11 = " *   Coded by Pixcher" fullword
    $s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
  condition:
    2 of them
}