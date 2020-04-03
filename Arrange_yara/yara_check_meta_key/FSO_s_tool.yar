rule FSO_s_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file tool.asp"
    family = "None"
    hacker = "None"
    hash = "3a1e1e889fdd974a130a6a767b42655b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "\"\"%windir%\\\\calc.exe\"\")"
  condition:
    all of them
}