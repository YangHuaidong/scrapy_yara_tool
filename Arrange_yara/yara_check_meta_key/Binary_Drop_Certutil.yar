rule Binary_Drop_Certutil {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-15"
    description = "Drop binary as base64 encoded cert trick"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/9DNn8q"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
    $s1 = "echo -----END CERTIFICATE----- >>" ascii
    $s2 = "certutil -decode " ascii
  condition:
    filesize < 10KB and all of them
}