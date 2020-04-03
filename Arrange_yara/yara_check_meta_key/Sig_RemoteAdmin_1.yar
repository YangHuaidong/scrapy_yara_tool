rule Sig_RemoteAdmin_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-03"
    description = "Detects strings from well-known APT malware"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 45
    threatname = "None"
    threattype = "None"
  strings:
    $ = "Radmin, Remote Administrator" wide
    $ = "Radmin 3.0" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}