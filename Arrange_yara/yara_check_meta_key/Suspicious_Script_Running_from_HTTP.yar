rule Suspicious_Script_Running_from_HTTP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-20"
    description = "Detects a suspicious "
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "cmd /C script:http://" ascii nocase
    $s2 = "cmd /C script:https://" ascii nocase
    $s3 = "cmd.exe /C script:http://" ascii nocase
    $s4 = "cmd.exe /C script:https://" ascii nocase
  condition:
    1 of them
}