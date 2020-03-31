rule Txt_ftp {
  meta:
    author = Spider
    comment = None
    date = 2015-06-14
    description = Chinese Hacktool Set - Webshells - file ftp.txt
    family = None
    hacker = None
    hash = 3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Txt[ftp
    threattype = ftp.yar
  strings:
    $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
    $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
    $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
    $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
    $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
    $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
    $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
  condition:
    filesize < 2KB and 2 of them
}