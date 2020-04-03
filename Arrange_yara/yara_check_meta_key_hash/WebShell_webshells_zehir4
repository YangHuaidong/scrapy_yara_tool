rule WebShell_webshells_zehir4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Github Archive - file zehir4"
    family = "None"
    hacker = "None"
    hash = "788928ae87551f286d189e163e55410acbb90a64"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
    $s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
  condition:
    1 of them
}