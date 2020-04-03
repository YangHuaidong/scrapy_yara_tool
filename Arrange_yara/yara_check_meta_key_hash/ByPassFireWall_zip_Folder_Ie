rule ByPassFireWall_zip_Folder_Ie {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file Ie.dll"
    family = "None"
    hacker = "None"
    hash = "d1b9058f16399e182c9b78314ad18b975d882131"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
    $s1 = "LOADER ERROR" fullword ascii
    $s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
    $s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
  condition:
    all of them
}