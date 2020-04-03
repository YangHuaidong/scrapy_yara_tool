rule ReactOS_cmd_valid {
  meta:
    author = "Spider"
    comment = "None"
    date = "05.11.14"
    description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
    family = "None"
    hacker = "None"
    hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
    score = 30
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ReactOS Command Processor" fullword wide
    $s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
    $s3 = "Eric Kohl and others" fullword wide
    $s4 = "ReactOS Operating System" fullword wide
  condition:
    all of ($s*)
}