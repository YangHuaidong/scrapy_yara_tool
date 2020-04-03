rule webshell_asp_Rader {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Rader.asp"
    family = "None"
    hacker = "None"
    hash = "ad1a362e0a24c4475335e3e891a01731"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
    $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
  condition:
    all of them
}