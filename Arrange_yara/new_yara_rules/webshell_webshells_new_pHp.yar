rule webshell_webshells_new_pHp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file pHp.php"
    family = "None"
    hacker = "None"
    hash = "b0e842bdf83396c3ef8c71ff94e64167"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
    $s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
    $s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
    $s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
    $s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
  condition:
    1 of them
}