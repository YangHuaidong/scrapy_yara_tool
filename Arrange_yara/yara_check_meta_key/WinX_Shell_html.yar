rule WinX_Shell_html {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file WinX Shell.html.txt"
    family = "None"
    hacker = "None"
    hash = "17ab5086aef89d4951fe9b7c7a561dda"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "WinX Shell"
    $s1 = "Created by greenwood from n57"
    $s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
  condition:
    2 of them
}