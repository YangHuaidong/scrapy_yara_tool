rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
    family = "None"
    hacker = "None"
    hash = "31e5473920a2cc445d246bc5820037d8fe383201"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "$content = chunk_split(base64_encode($content)); " fullword
    $s12 = "print \"Sending mail to $to....... \"; " fullword
    $s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword
  condition:
    all of them
}