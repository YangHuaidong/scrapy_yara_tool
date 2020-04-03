rule HawkEye_PHP_Panel {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/14"
    description = "Detects HawkEye Keyloggers PHP Panel"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$fname = $_GET['fname'];" ascii fullword
    $s1 = "$data = $_GET['data'];" ascii fullword
    $s2 = "unlink($fname);" ascii fullword
    $s3 = "echo \"Success\";" fullword ascii
  condition:
    all of ($s*) and filesize < 600
}