rule sig_238_webget {
   meta:
      description = "Disclosed hacktool set (old stuff) - file webget.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
   strings:
      $s0 = "Packed by exe32pack" ascii
      $s1 = "GET A HTTP/1.0" fullword ascii
      $s2 = " error " fullword ascii
      $s13 = "Downloa" ascii
   condition:
      all of them
}