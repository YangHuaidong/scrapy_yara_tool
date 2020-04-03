rule Hacktools_CN_WinEggDrop {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file s.exe"
    family = "None"
    hacker = "None"
    hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
    $s2 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
    $s6 = "Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner" fullword ascii
    $s8 = "Something Wrong About The Ports" fullword ascii
    $s9 = "Performing Time: %d/%d/%d %d:%d:%d --> " fullword ascii
    $s10 = "Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save" fullword ascii
    $s12 = "%u Ports Scanned.Taking %d Threads " fullword ascii
    $s13 = "%-16s %-5d -> \"%s\"" fullword ascii
    $s14 = "SYN Scan Can Only Perform On WIN 2K Or Above" fullword ascii
    $s17 = "SYN Scan: About To Scan %s:%d Using %d Thread" fullword ascii
    $s18 = "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports" fullword ascii
  condition:
    5 of them
}