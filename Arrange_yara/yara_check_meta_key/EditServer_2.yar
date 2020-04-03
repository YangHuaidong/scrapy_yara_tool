rule EditServer_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file EditServer.exe"
    family = "None"
    hacker = "None"
    hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "@HOTMAIL.COM"
    $s1 = "Press Any Ke"
    $s3 = "glish MenuZ"
  condition:
    all of them
}