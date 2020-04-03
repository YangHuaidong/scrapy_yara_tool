rule Unpack_TBack {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file TBack.dll"
    family = "None"
    hacker = "None"
    hash = "a9d1007823bf96fb163ab38726b48464"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "\\final\\new\\lcc\\public.dll"
  condition:
    all of them
}