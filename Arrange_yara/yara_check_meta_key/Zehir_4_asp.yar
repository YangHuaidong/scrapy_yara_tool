rule Zehir_4_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
    family = "None"
    hacker = "None"
    hash = "7f4e12e159360743ec016273c3b9108c"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
    $s4 = "<input type=submit value=\"Test Et!\" onclick=\""
  condition:
    1 of them
}