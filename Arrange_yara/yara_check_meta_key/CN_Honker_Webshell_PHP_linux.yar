rule CN_Honker_Webshell_PHP_linux {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
    family = "None"
    hacker = "None"
    hash = "78339abb4e2bb00fe8a012a0a5b7ffce305f4e06"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
  condition:
    uint16(0) == 0x696c and filesize < 6KB and all of them
}