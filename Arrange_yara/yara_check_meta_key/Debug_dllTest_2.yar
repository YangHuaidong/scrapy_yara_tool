rule Debug_dllTest_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dllTest.dll"
    family = "None"
    hacker = "None"
    hash = "1b9e518aaa62b15079ff6edb412b21e9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "\\Debug\\dllTest.pdb"
    $s5 = "--list the services in the computer"
  condition:
    all of them
}