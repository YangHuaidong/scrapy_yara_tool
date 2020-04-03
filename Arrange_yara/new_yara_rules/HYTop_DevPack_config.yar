rule HYTop_DevPack_config {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file config.asp"
    family = "None"
    hacker = "None"
    hash = "b41d0e64e64a685178a3155195921d61"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "const adminPassword=\""
    $s2 = "const userPassword=\""
    $s3 = "const mVersion="
  condition:
    all of them
}