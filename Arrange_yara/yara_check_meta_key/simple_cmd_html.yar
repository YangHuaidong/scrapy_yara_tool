rule simple_cmd_html {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file simple_cmd.html.txt"
    family = "None"
    hacker = "None"
    hash = "c6381412df74dbf3bcd5a2b31522b544"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<title>G-Security Webshell</title>" fullword
    $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
    $s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
    $s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
  condition:
    all of them
}