rule FSO_s_zehir4_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file zehir4.asp"
    family = "None"
    hacker = "None"
    hash = "5b496a61363d304532bcf52ee21f5d55"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "\"Program Files\\Serv-u\\Serv"
  condition:
    all of them
}