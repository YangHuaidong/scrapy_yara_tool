rule apt_RU_MoonlightMaze_customsniffer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-15"
    description = "Rule to detect Moonlight Maze sniffer tools"
    family = "None"
    hacker = "None"
    hash = "7b86f40e861705d59f5206c482e1f2a5"
    hash = "927426b558888ad680829bd34b0ad0e7"
    judge = "black"
    original_filename = "ora;tdn"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    threatname = "None"
    threattype = "None"
    version = "1.1"
  strings:
    $a1 = "/var/tmp/gogo" fullword
    $a2 = "myfilename= |%s|" fullword
    $a3 = "mypid,mygid=" fullword
    $a4 = "mypid=|%d| mygid=|%d|" fullword
    $a5 = "/var/tmp/task" fullword
    $a6 = "mydevname= |%s|" fullword
  condition:
    2 of ($a*)
}