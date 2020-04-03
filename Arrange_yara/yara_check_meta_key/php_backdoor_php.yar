rule php_backdoor_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file php-backdoor.php.txt"
    family = "None"
    hacker = "None"
    hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://michaeldaw.org   2006"
    $s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
    $s3 = "coded by z0mbie"
  condition:
    1 of them
}