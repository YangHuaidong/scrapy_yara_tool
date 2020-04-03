rule webshell_php_moon {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file moon.php"
    family = "None"
    hacker = "None"
    hash = "2a2b1b783d3a2fa9a50b1496afa6e356"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "echo '<option value=\"create function backshell returns string soname"
    $s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
    $s8 = "echo '<option value=\"select cmdshell(\\'net user "
  condition:
    2 of them
}