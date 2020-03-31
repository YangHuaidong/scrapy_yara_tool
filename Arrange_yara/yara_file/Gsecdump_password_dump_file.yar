rule Gsecdump_password_dump_file {
   meta:
      description = "Detects a gsecdump output file"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://t.co/OLIj1yVJ4m"
      date = "2018-03-06"
      score = 65
   strings:
      $x1 = "Administrator(current):500:" ascii
   condition:
      uint32be(0) == 0x41646d69 and filesize < 3000 and $x1 at 0
}