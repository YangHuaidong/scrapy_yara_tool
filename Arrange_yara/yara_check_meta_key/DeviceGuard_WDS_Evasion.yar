rule DeviceGuard_WDS_Evasion {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detects WDS file used to circumvent Device Guard"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "r @$ip=@$t0" ascii fullword
    $s2 = ";eb @$t0+" ascii
    $s3 = ".foreach /pS" ascii fullword
  condition:
    filesize < 50KB and all of them
}