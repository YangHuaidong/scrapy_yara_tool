rule PortScanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file PortScanner.exe"
    family = "None"
    hacker = "None"
    hash = "b381b9212282c0c650cb4b0323436c63"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Scan Ports Every"
    $s3 = "Scan All Possible Ports!"
  condition:
    all of them
}