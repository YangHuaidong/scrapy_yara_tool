rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
    family = "None"
    hacker = "None"
    hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
    hash1 = "911195a9b7c010f61b66439d9048f400"
    hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
    $s1 = "$name='ec371748dc2da624b35a4f8f685dd122'"
    $s2 = "rst.void.ru"
  condition:
    3 of them
}