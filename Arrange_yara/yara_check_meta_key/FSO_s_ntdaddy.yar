rule FSO_s_ntdaddy {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ntdaddy.asp"
    family = "None"
    hacker = "None"
    hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
  condition:
    all of them
}