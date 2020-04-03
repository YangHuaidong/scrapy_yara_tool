rule apt_RU_MoonlightMaze_cle_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-27"
    description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
    family = "None"
    hacker = "None"
    hash = "647d7b711f7b4434145ea30d0ef207b0"
    judge = "black"
    last_modified = "2017-03-27"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "./a filename template_file" ascii wide
    $a2 = "May be %s is empty?"  ascii wide
    $a3 = "template string = |%s|"   ascii wide
    $a4 = "No blocks !!!"
    $a5 = "No data in this block !!!!!!"  ascii wide
    $a6 = "No good line"
  condition:
    ((3 of ($a*)))
}