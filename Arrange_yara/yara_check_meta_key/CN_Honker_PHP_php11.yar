rule CN_Honker_PHP_php11 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file php11.txt"
    family = "None"
    hacker = "None"
    hash = "dcc8226e7eb20e4d4bef9e263c14460a7ee5e030"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<tr><td><b><?php if (!$win) {echo wordwrap(myshellexec('id'),90,'<br>',1);} else" ascii /* PEStudio Blacklist: strings */
    $s2 = "foreach (glob($_GET['pathtomass'].\"/*.htm\") as $injectj00) {" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "echo '[cPanel Found] '.$login.':'.$pass.\"  Success\\n\";" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 800KB and all of them
}