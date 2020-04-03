rule sig_238_Glass2k {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
    family = "None"
    hacker = "None"
    hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
    $s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
    $s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
    $s4 = "Glass2k.exe" fullword wide
    $s7 = "NeoLite Executable File Compressor" fullword ascii
  condition:
    all of them
}