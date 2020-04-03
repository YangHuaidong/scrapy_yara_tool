rule webshell_asp_dabao {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file dabao.asp"
    family = "None"
    hacker = "None"
    hash = "3919b959e3fa7e86d52c2b0a91588d5d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
    $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
  condition:
    all of them
}