rule PortRacer {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file PortRacer.exe"
    family = "None"
    hacker = "None"
    hash = "2834a872a0a8da5b1be5db65dfdef388"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Auto Scroll BOTH Text Boxes"
    $s4 = "Start/Stop Portscanning"
    $s6 = "Auto Save LogFile by pressing STOP"
  condition:
    all of them
}