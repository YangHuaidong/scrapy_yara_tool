rule WindowsCredentialEditor {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Windows Credential Editor"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 90
    threat_level = 10
    threatname = "None"
    threattype = "None"
  strings:
    $a = "extract the TGT session key"
    $b = "Windows Credentials Editor"
  condition:
    all of them
}