rule webshell_Ani_Shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Ani-Shell.php"
    family = "None"
    hacker = "None"
    hash = "889bfc9fbb8ee7832044fc575324d01a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$Python_CODE = \"I"
    $s6 = "$passwordPrompt = \"\\n================================================="
    $s7 = "fputs ($sockfd ,\"\\n==============================================="
  condition:
    1 of them
}