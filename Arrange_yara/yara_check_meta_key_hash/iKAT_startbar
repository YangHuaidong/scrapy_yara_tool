rule iKAT_startbar {
  meta:
    author = "Spider"
    comment = "None"
    date = "05.11.14"
    description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
    family = "None"
    hacker = "None"
    hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Shinysoft Limited1" fullword ascii
    $s3 = "Shinysoft Limited0" fullword ascii
    $s4 = "Wellington1" fullword ascii
    $s6 = "Wainuiomata1" fullword ascii
    $s8 = "56 Wright St1" fullword ascii
    $s9 = "UTN-USERFirst-Object" fullword ascii
    $s10 = "New Zealand1" fullword ascii
  condition:
    all of them
}