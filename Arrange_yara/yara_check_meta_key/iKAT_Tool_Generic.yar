rule iKAT_Tool_Generic {
  meta:
    author = "Spider"
    comment = "None"
    date = "05.11.14"
    description = "Generic Rule for hack tool iKAT files gpdisable.exe, kitrap0d.exe, uacpoc.exe"
    family = "None"
    hacker = "None"
    hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
    hash1 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
    hash2 = "b65a460d015fd94830d55e8eeaf6222321e12349"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
    score = 55
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<IconFile>C:\\WINDOWS\\App.ico</IconFile>" fullword
    $s1 = "Failed to read the entire file" fullword
    $s4 = "<VersionCreatedBy>14.4.0</VersionCreatedBy>" fullword
    $s8 = "<ProgressCaption>Run &quot;executor.bat&quot; once the shell has spawned.</P"
    $s9 = "Running Zip pipeline..." fullword
    $s10 = "<FinTitle />" fullword
    $s12 = "<AutoTemp>0</AutoTemp>" fullword
    $s14 = "<DefaultDir>%TEMP%</DefaultDir>" fullword
    $s15 = "AES Encrypting..." fullword
    $s20 = "<UnzipDir>%TEMP%</UnzipDir>" fullword
  condition:
    all of them
}