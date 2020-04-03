rule FeliksPack3___PHP_Shells_phpft {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpft.php"
    family = "None"
    hacker = "None"
    hash = "60ef80175fcc6a879ca57c54226646b1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s6 = "PHP Files Thief"
    $s11 = "http://www.4ngel.net"
  condition:
    all of them
}