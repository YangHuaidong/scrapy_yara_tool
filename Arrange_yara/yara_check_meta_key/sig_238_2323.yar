rule sig_238_2323 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file 2323.exe"
    family = "None"
    hacker = "None"
    hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "port - Port to listen on, defaults to 2323" fullword ascii
    $s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
    $s3 = "Failed to execute shell" fullword ascii
    $s5 = "/h   - Hide Window" fullword ascii
    $s7 = "Accepted connection from client at %s" fullword ascii
    $s9 = "Error %d: %s" fullword ascii
  condition:
    all of them
}