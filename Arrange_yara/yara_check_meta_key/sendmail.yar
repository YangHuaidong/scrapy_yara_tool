rule sendmail {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file sendmail.exe"
    family = "None"
    hacker = "None"
    hash = "75b86f4a21d8adefaf34b3a94629bd17"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "_NextPyC808"
    $s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
  condition:
    all of them
}