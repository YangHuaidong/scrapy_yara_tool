rule webshell_Shell_ci_Biz_was_here_c100_v_xxx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell"
    family = "None"
    hacker = "None"
    hash0 = "f2fa878de03732fbf5c86d656467ff50"
    hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
    hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
    $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
    $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
    $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
    $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
  condition:
    2 of them
}