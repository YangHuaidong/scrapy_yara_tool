rule h4ntu_shell__powered_by_tsoi_ {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
    family = "None"
    hacker = "None"
    hash = "06ed0b2398f8096f1bebf092d0526137"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "h4ntu shell"
    $s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
  condition:
    1 of them
}