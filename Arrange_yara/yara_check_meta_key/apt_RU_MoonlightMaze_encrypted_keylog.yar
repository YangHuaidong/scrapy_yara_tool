rule apt_RU_MoonlightMaze_encrypted_keylog {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-27"
    description = "Rule to detect Moonlight Maze encrypted keylogger logs"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2017-03-27"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = { 47 01 22 2a 6d 3e 39 2c }
  condition:
    uint32(0) == 0x2a220147 and ($a1 at 0)
}