rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
    family = "None"
    hacker = "None"
    hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
    $s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
    $s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
  condition:
    1 of them
}