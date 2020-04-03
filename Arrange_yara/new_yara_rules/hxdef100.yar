rule hxdef100 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hxdef100.exe"
    family = "None"
    hacker = "None"
    hash = "55cc1769cef44910bd91b7b73dee1f6c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "RtlAnsiStringToUnicodeString"
    $s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
    $s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
  condition:
    all of them
}