rule churrasco {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file churrasco.exe"
    family = "None"
    hacker = "None"
    hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Done, command should have ran as SYSTEM!" ascii
    $s2 = "Running command with SYSTEM Token..." ascii
    $s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
    $s4 = "Found SYSTEM token 0x%x" ascii
    $s5 = "Thread not impersonating, looking for another thread..." ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}