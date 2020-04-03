rule CN_Tools_hscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file hscan.exe"
    family = "None"
    hacker = "None"
    hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
    $s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
    $s3 = "%s -h www.target.com -all" fullword ascii
    $s4 = ".\\report\\%s-%s.html" fullword ascii
    $s5 = ".\\log\\Hscan.log" fullword ascii
    $s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
    $s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
    $s8 = ".\\conf\\mysql_pass.dic" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}