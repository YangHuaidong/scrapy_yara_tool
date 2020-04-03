rule shankar_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file shankar.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "6eb9db6a3974e511b7951b8f7e7136bb"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $sAuthor = "ShAnKaR"
    $s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
    $s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
  condition:
    1 of ($s*) and $sAuthor
}