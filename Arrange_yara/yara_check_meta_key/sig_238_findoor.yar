rule sig_238_findoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file findoor.exe"
    family = "None"
    hacker = "None"
    hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
    $s8 = "PASS hacker@hacker.com" fullword ascii
    $s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
    $s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
    $s11 = "http://isno.yeah.net" fullword ascii
  condition:
    4 of them
}