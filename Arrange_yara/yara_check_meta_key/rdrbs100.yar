rule rdrbs100 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file rdrbs100.exe"
    family = "None"
    hacker = "None"
    hash = "7c752bcd6da796d80a6830c61a632bff"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "Server address must be IP in A.B.C.D format."
    $s4 = " mapped ports in the list. Currently "
  condition:
    all of them
}