rule HScan_v1_20_hscan {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file hscan.exe
    family = hscan
    hacker = None
    hash = 568b06696ea0270ee1a744a5ac16418c8dacde1c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = HScan[v1]/20.hscan
    threattype = v1
  strings:
    $s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
    $s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
    $s3 = ".\\report\\%s-%s.html" fullword ascii
    $s4 = ".\\log\\Hscan.log" fullword ascii
    $s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}