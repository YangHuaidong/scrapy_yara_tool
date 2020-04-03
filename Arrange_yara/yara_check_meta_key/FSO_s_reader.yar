rule FSO_s_reader {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file reader.asp"
    family = "None"
    hacker = "None"
    hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "mailto:mailbomb@hotmail."
  condition:
    all of them
}