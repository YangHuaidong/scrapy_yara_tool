rule HYTop_DevPack_upload {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file upload.asp"
    family = "None"
    hacker = "None"
    hash = "b09852bda534627949f0259828c967de"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<!-- PageUpload Below -->"
  condition:
    all of them
}