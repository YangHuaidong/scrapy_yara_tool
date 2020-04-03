rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file mail.php"
    family = "None"
    hacker = "None"
    hash = "0a9b7b438591ee78ee573028cbb805a9dbb9da96"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 39KB and all of them
}