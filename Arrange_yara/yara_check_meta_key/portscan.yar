rule portscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file portscan.exe"
    family = "None"
    hacker = "None"
    hash = "a8bfdb2a925e89a281956b1e3bb32348"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "0    :SCAN BEGUN ON PORT:"
    $s6 = "0    :PORTSCAN READY."
  condition:
    all of them
}