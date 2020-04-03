rule apt_RU_MoonlightMaze_wipe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-27"
    description = "Rule to detect log cleaner based on wipe.c"
    family = "None"
    hacker = "None"
    hash = "e69efc504934551c6a77b525d5343241"
    judge = "black"
    last_modified = "2017-03-27"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    reference2 = "http://www.afn.org/~afn28925/wipe.c"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "ERROR: Unlinking tmp WTMP file."
    $a2 = "USAGE: wipe [ u|w|l|a ] ...options..."
    $a3 = "Erase acct entries on tty :   wipe a [username] [tty]"
    $a4 = "Alter lastlog entry       :   wipe l [username] [tty] [time] [host]"
  condition:
    (uint32(0)==0x464c457f) and (2 of them)
}