rule Mithril_dllTest {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dllTest.dll"
    family = "None"
    hacker = "None"
    hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "please enter the password:"
    $s3 = "\\dllTest.pdb"
  condition:
    all of them
}