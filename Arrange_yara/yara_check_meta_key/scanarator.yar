rule scanarator {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file scanarator.exe"
    family = "None"
    hacker = "None"
    hash = "848bd5a518e0b6c05bd29aceb8536c46"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
  condition:
    all of them
}