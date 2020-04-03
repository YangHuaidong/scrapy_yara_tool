rule CN_Toolset_sig_1433_135_sqlr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/30"
    description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
    family = "None"
    hacker = "None"
    hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://qiannao.com/ls/905300366/33834c0c/"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
    $s11 = ";DATABASE=master" fullword ascii
    $s12 = "xp_cmdshell '" fullword ascii
    $s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
  condition:
    all of them
}