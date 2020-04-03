rule Project1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Project1.exe"
    family = "None"
    hacker = "None"
    hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
    $s2 = "Password.txt" fullword ascii
    $s3 = "LoginPrompt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}