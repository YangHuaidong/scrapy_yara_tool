rule Dive_Shell_1_0___Emperor_Hacking_Team_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt
    family = 0
    hacker = None
    hash = 1b5102bdc41a7bc439eea8f0010310a5
    judge = unknown
    reference = None
    threatname = Dive[Shell]/1.0...Emperor.Hacking.Team.php
    threattype = Shell
  strings:
    $s0 = "Emperor Hacking TEAM"
    $s1 = "Simshell" fullword
    $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
    $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"
  condition:
    2 of them
}