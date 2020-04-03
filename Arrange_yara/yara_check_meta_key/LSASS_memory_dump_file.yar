rule LSASS_memory_dump_file {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/31"
    description = "Detects a LSASS memory dump file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    memory = 0
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "lsass.exe" ascii fullword
    $s2 = "wdigest.DLL" wide nocase
  condition:
    uint32(0) == 0x504D444D and all of them
}