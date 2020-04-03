rule IP_Stealing_Utilities {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file IP Stealing Utilities.exe"
    family = "None"
    hacker = "None"
    hash = "65646e10fb15a2940a37c5ab9f59c7fc"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "DarkKnight"
    $s9 = "IPStealerUtilities"
  condition:
    all of them
}