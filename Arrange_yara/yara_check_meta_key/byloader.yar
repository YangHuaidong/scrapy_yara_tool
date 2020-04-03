rule byloader {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file byloader.exe"
    family = "None"
    hacker = "None"
    hash = "0f0d6dc26055653f5844ded906ce52df"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
    $s1 = "Failure ... Access is Denied !"
    $s2 = "NTFS Disk Driver Checking Service"
    $s3 = "Dumping Description to Registry..."
    $s4 = "Opening Service .... Failure !"
  condition:
    all of them
}