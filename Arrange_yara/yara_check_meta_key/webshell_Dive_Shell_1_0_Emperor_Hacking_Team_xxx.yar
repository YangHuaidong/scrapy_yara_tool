rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell"
    family = "None"
    hacker = "None"
    hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
    hash1 = "f8a6d5306fb37414c5c772315a27832f"
    hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
    $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
  condition:
    all of them
}