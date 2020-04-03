rule _hscan_hscan_hscangui {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
    family = "None"
    hacker = "None"
    hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
    hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
    hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".\\log\\Hscan.log" fullword ascii
    $s2 = ".\\report\\%s-%s.html" fullword ascii
    $s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
    $s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
    $s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 240KB and all of them
}