rule apt_equation_cryptotable {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect the crypto library used in Equation group malware"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2015-02-16"
    reference = "https://securelist.com/blog/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a = { 37 df e8 b6 c7 9c 0b ae 91 ef f0 3b 90 c6 80 85 5d 19 4b 45 44 12 3c e2 0d 5c 1c 7b c4 ff d6 05 17 14 4f 03 74 1e 41 da 8f 7d de 7e 99 f1 35 ac b8 46 93 ce 23 82 07 eb 2b d4 72 71 40 f3 b0 f7 78 d7 4c d1 55 1a 39 83 18 fa e1 9a 56 b1 96 ab a6 30 c5 5f be 0c 50 c1 }
  condition:
    $a
}