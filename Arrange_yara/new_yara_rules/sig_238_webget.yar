rule sig_238_webget {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file webget.exe"
    family = "None"
    hacker = "None"
    hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Packed by exe32pack" ascii
    $s1 = "GET A HTTP/1.0" fullword ascii
    $s2 = " error " fullword ascii
    $s13 = "Downloa" ascii
  condition:
    all of them
}