rule CN_Honker_Webshell_WebShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
    family = "None"
    hacker = "None"
    hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "warn \"command: '$command'\\n\";" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 30KB and 2 of them
}