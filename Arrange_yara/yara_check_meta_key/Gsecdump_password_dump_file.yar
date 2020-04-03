rule Gsecdump_password_dump_file {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-06"
    description = "Detects a gsecdump output file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://t.co/OLIj1yVJ4m"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Administrator(current):500:" ascii
  condition:
    uint32be(0) == 0x41646d69 and filesize < 3000 and $x1 at 0
}