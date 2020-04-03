rule apt_RU_MoonlightMaze_u_logcleaner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-27"
    description = "Rule to detect log cleaners based on utclean.c"
    family = "None"
    hacker = "None"
    hash = "d98796dcda1443a37b124dbdc041fe3b"
    hash = "73a518f0a73ab77033121d4191172820"
    judge = "black"
    last_modified = "2017-03-27"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    reference2 = "http://cd.textfiles.com/cuteskunk/Unix-Hacking-Exploits/utclean.c"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "Hiding complit...n"
    $a2 = "usage: %s <username> <fixthings> [hostname]"
    $a3 = "ls -la %s* ; /bin/cp  ./wtmp.tmp %s; rm  ./wtmp.tmp"
  condition:
    (uint32(0)==0x464c457f) and (any of them)
}