rule Hacktools_CN_Burst_Blast {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file Blast.bat"
    family = "None"
    hacker = "None"
    hash = "b07702a381fa2eaee40b96ae2443918209674051"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
    $s1 = "@echo off" fullword ascii
  condition:
    all of them
}