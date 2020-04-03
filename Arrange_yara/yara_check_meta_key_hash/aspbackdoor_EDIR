rule aspbackdoor_EDIR {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
    family = "None"
    hacker = "None"
    hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "response.write \"<a href='index.asp'>" fullword ascii
    $s3 = "if Request.Cookies(\"password\")=\"" ascii
    $s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
    $s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
    $s19 = "whichdir=Request(\"path\")" fullword ascii
  condition:
    all of them
}