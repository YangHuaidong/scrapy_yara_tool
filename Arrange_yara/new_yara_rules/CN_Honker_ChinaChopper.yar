rule CN_Honker_ChinaChopper {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ChinaChopper.exe"
    family = "None"
    hacker = "None"
    hash = "fa347fdb23ab0b8d0560a0d20c434549d78e99b5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$m=get_magic_quotes_gpc();$sid=$m?stripslashes($_POST[\"z1\"]):$_POST[\"z1\"];$u" wide /* PEStudio Blacklist: strings */
    $s3 = "SETP c:\\windows\\system32\\cmd.exe " fullword wide /* PEStudio Blacklist: strings */
    $s4 = "Ev al (\"Exe cute(\"\"On+Error+Resume+Next:%s:Response.Write(\"\"\"\"->|\"\"\"\"" wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}