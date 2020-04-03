rule PassSniffer_zip_Folder_readme {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file readme.txt"
    family = "None"
    hacker = "None"
    hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "PassSniffer.exe" fullword ascii
    $s1 = "POP3/FTP Sniffer" fullword ascii
    $s2 = "Password Sniffer V1.0" fullword ascii
  condition:
    1 of them
}