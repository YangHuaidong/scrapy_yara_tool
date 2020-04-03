rule iKAT_tools_nmap {
  meta:
    author = "Spider"
    comment = "None"
    date = "05.11.14"
    description = "Generic rule for NMAP - based on NMAP 4 standalone"
    family = "None"
    hacker = "None"
    hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Insecure.Org" fullword wide
    $s1 = "Copyright (c) Insecure.Com" fullword wide
    $s2 = "nmap" fullword nocase
    $s3 = "Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm)." ascii
  condition:
    all of them
}