rule FSO_s_ajan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ajan.asp"
    family = "None"
    hacker = "None"
    hash = "22194f8c44524f80254e1b5aec67b03e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "entrika.write \"BinaryStream.SaveToFile"
  condition:
    all of them
}