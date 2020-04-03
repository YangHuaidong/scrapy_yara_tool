rule Antiy_Ports_1_21 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
    family = "None"
    hacker = "None"
    hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "AntiyPorts.EXE" fullword wide
    $s7 = "AntiyPorts MFC Application" fullword wide
    $s20 = " @Stego:" fullword ascii
  condition:
    all of them
}