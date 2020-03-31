rule Txt_Sql {
  meta:
    author = Spider
    comment = None
    date = 2015-06-14
    description = Chinese Hacktool Set - Webshells - file Sql.txt
    family = None
    hacker = None
    hash = f7813f1dfa4eec9a90886c80b88aa38e2adc25d5
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Txt[Sql
    threattype = Sql.yar
  strings:
    $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
    $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
    $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
    $s4 = "session(\"login\")=\"\"" fullword ascii
  condition:
    filesize < 15KB and all of them
}