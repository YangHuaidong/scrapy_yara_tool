rule byshell063_ntboot {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ntboot.exe"
    family = "None"
    hacker = "None"
    hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
    $s1 = "Failure ... Access is Denied !"
    $s2 = "Dumping Description to Registry..."
    $s3 = "Opening Service .... Failure !"
  condition:
    all of them
}