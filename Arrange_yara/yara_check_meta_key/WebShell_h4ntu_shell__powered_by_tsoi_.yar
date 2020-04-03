rule WebShell_h4ntu_shell__powered_by_tsoi_ {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
    family = "None"
    hacker = "None"
    hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
    $s13 = "$cmd = $_POST['cmd'];" fullword
    $s16 = "$uname = posix_uname( );" fullword
    $s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
    $s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
    $s20 = "ob_end_clean();" fullword
  condition:
    3 of them
}