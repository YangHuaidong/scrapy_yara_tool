rule ReconCommands_in_File {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-11"
    description = "Detects various recon commands in a single file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/haroonmeer/status/939099379834658817"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $ = "tasklist"
    $ = "net time"
    $ = "systeminfo"
    $ = "whoami"
    $ = "nbtstat"
    $ = "net start"
    $ = "qprocess"
    $ = "nslookup"
  condition:
    filesize < 5KB and 4 of them
}