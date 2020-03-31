rule stealth_Stealth {
  meta:
    author = Spider
    comment = None
    date = None
    description = Auto-generated rule on file Stealth.exe
    family = None
    hacker = None
    hash = 8ce3a386ce0eae10fc2ce0177bbc8ffa
    judge = unknown
    reference = None
    threatname = stealth[Stealth
    threattype = Stealth.yar
  strings:
    $s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
    $s6 = "This tool may be used only by system administrators. I am not responsible for "
  condition:
    all of them
}