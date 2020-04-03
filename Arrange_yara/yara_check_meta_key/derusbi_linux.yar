rule derusbi_linux {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-09"
    description = "Derusbi Server Linux version"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
    $cmd = "unset LS_OPTIONS;uname -a"
    $pname = "[diskio]"
    $rkfile = "/tmp/.secure"
    $ELF = "\x7fELF"
  condition:
    $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}