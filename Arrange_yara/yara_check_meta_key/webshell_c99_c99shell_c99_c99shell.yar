rule webshell_c99_c99shell_c99_c99shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
    family = "None"
    hacker = "None"
    hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
    hash1 = "d3f38a6dc54a73d304932d9227a739ec"
    hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
    hash3 = "048ccc01b873b40d57ce25a4c56ea717"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "$bindport_pass = \"c99\";" fullword
    $s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
  condition:
    1 of them
}