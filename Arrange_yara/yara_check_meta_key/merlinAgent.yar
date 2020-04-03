rule merlinAgent {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-26"
    description = "Detects Merlin agent"
    family = "None"
    filetype = "pe, elf, mach"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/Ne0nd0g/merlin"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Command output:\x0d\x0a\x0d\x0a%s"
    $x2 = "[-]Connecting to web server at %s to update agent configuration information."
    $x3 = "[-]%d out of %d total failed checkins"
    $x4 = "[!}Unknown AgentControl message type received %s"
    $x5 = "[-]Received Agent Kill Message"
    $x6 = "[-]Received Server OK, doing nothing"
    $x7 = "[!]There was an error with the HTTP client while performing a POST:"
    $x8 = "[-]Sleeping for %s at %s"
    $s1 = "Executing command %s %s %s"
    $s2 = "[+]Host Information:"
    $s3 = "\tHostname: %s"
    $s4 = "\tPlatform: %s"
    $s5 = "\tUser GUID: %s"
  condition:
    1 of ($x*) or 4 of them
}