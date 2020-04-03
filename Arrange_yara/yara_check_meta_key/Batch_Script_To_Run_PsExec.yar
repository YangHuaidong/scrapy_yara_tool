rule Batch_Script_To_Run_PsExec {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018/04/06"
    description = "Detects malicious batch file from NCSC report"
    family = "None"
    hacker = "None"
    hash = "b7d7c4bc8f9fd0e461425747122a431f93062358ed36ce281147998575ee1a18"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "Tokens=1 delims=" ascii
    $ = "SET ws=%1" ascii
    $ = "Checking %ws%" ascii
    $ = "%TEMP%\\%ws%ns.txt" ascii
    $ = "ps.exe -accepteula" ascii
  condition:
    3 of them
}