rule CobaltStrike_Unmodifed_Beacon {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-16"
    description = "Detects unmodified CobaltStrike beacon DLL"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $loader_export = "ReflectiveLoader"
    $exportname = "beacon.dll"
  condition:
    all of them
}