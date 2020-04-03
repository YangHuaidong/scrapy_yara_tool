rule SecurityXploded_Producer_String {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-13"
    description = "Detects hacktools by SecurityXploded"
    family = "None"
    hacker = "None"
    hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://securityxploded.com/browser-password-dump.php"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "http://securityxploded.com" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and all of them )
}