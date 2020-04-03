rule URL_File_Local_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-04"
    description = "Detects an .url file that points to a local executable"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/malwareforme/status/915300883012870144"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[InternetShortcut]" ascii wide fullword
    $s2 = /URL=file:\/\/\/C:\\[^\n]{1,50}\.exe/
  condition:
    filesize < 400 and all of them
}