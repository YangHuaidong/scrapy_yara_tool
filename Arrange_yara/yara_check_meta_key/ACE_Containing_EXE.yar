rule ACE_Containing_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-09-09"
    description = "Looks for ACE Archives containing an exe/scr file"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $header = { 2a 2a 41 43 45 2a 2a }
    $extensions1 = ".exe"
    $extensions2 = ".EXE"
    $extensions3 = ".scr"
    $extensions4 = ".SCR"
  condition:
    $header at 7 and for
    any of ($extensions*): (
    $ in (81..(81+uint16(79)))
}