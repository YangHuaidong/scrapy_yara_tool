rule sig_238_hunt {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file hunt.exe"
    family = "None"
    hacker = "None"
    hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
    $s3 = "Usage - hunt \\\\servername" fullword ascii
    $s4 = ".share = %S - %S" fullword wide
    $s5 = "SMB share enumerator and admin finder " fullword ascii
    $s7 = "Hunt only runs on Windows NT..." fullword ascii
    $s8 = "User = %S" fullword ascii
    $s9 = "Admin is %s\\%s" fullword ascii
  condition:
    all of them
}