rule WebShell_dC3_Security_Crew_Shell_PRiV_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
    family = "None"
    hacker = "None"
    hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
    $s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
    $s13 = "header(\"Content-type: image/gif\");" fullword
    $s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
    $s20 = "if (isset($_GET['rename_all'])) {" fullword
  condition:
    3 of them
}