rule webshell_phpspy2010 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file phpspy2010.php"
    family = "None"
    hacker = "None"
    hash = "14ae0e4f5349924a5047fed9f3b105c5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "eval(gzinflate(base64_decode("
    $s5 = "//angel" fullword
    $s8 = "$admin['cookiedomain'] = '';" fullword
  condition:
    all of them
}