rule LinuxHacktool_eyes_pscan2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/01/19"
    description = "Linux hack tools - file pscan2"
    family = "None"
    hacker = "None"
    hash = "56b476cba702a4423a2d805a412cae8ef4330905"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
    $s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
    $s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
    $s8 = "Invalid IP." fullword ascii
    $s9 = "# scanning: " fullword ascii
    $s10 = "Unable to allocate socket." fullword ascii
  condition:
    2 of them
}