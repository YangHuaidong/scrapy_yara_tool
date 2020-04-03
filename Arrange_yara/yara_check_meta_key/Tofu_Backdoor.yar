rule Tofu_Backdoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-28"
    description = "Detects Tofu Trojan"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "Cookies: Sym1.0"
    $b = "\\\\.\\pipe\\1[12345678]"
    $c = { 66 0f fc c1 0f 11 40 d0 0f 10 40 d0 66 0f ef c2 0f 11 40 d0 0f 10 40 e0 }
  condition:
    $a or $b or $c
}