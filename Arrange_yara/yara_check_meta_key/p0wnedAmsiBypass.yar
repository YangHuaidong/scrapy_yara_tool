rule p0wnedAmsiBypass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-14"
    description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
    family = "None"
    hacker = "None"
    hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Cn33liz/p0wnedShell"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Program.P0wnedPath()" fullword ascii
    $x2 = "namespace p0wnedShell" fullword ascii
    $x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii
  condition:
    1 of them
}