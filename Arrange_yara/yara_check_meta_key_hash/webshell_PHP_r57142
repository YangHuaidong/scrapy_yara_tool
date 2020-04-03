rule webshell_PHP_r57142 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file r57142.php"
    family = "None"
    hacker = "None"
    hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
  condition:
    all of them
}