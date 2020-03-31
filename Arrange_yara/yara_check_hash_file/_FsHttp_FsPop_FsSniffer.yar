rule _FsHttp_FsPop_FsSniffer {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe
    family = FsSniffer
    hacker = None
    hash0 = 9d4e7611a328eb430a8bb6dc7832440713926f5f
    hash1 = ae23522a3529d3313dd883727c341331a1fb1ab9
    hash2 = 7ffc496cd4a1017485dfb571329523a52c9032d8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    super_rule = 1
    threatname = [FsHttp]/FsPop.FsSniffer
    threattype = FsHttp
  strings:
    $s0 = "-ERR Invalid Command, Type [Help] For Command List" fullword
    $s1 = "-ERR Get SMS Users ID Failed" fullword
    $s2 = "Control Time Out 90 Secs, Connection Closed" fullword
    $s3 = "-ERR Post SMS Failed" fullword
    $s4 = "Current.hlt" fullword
    $s6 = "Histroy.hlt" fullword
    $s7 = "-ERR Send SMS Failed" fullword
    $s12 = "-ERR Change Password <New Password>" fullword
    $s17 = "+OK Send SMS Succussifully" fullword
    $s18 = "+OK Set New Password: [%s]" fullword
    $s19 = "CHANGE PASSWORD" fullword
  condition:
    all of them
}