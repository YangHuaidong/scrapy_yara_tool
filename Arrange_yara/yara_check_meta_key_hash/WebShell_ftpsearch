rule WebShell_ftpsearch {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file ftpsearch.php"
    family = "None"
    hacker = "None"
    hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
    $s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
    $s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
    $s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword
  condition:
    2 of them
}