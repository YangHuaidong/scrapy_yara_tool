rule PassSniffer_zip_Folder_readme {
   meta:
      description = "Disclosed hacktool set (old stuff) - file readme.txt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
   strings:
      $s0 = "PassSniffer.exe" fullword ascii
      $s1 = "POP3/FTP Sniffer" fullword ascii
      $s2 = "Password Sniffer V1.0" fullword ascii
   condition:
      1 of them
}