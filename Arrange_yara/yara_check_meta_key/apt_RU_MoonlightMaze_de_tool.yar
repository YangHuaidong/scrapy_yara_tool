rule apt_RU_MoonlightMaze_de_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-27"
    description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
    family = "None"
    hacker = "None"
    hash = "4bc7ed168fb78f0dc688ee2be20c9703"
    hash = "8b56e8552a74133da4bc5939b5f74243"
    judge = "black"
    last_modified = "2017-03-27"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "Vnuk: %d" ascii fullword
    $a2 = "Syn: %d" ascii fullword
    $a3 = { 25 73 0a 25 73 0a 25 73 0a 25 73 0a }
  condition:
    ((2 of ($a*)))
}