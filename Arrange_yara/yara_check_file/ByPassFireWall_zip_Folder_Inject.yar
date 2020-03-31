rule ByPassFireWall_zip_Folder_Inject {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - file Inject.exe
    family = Inject
    hacker = None
    hash = 34f564301da528ce2b3e5907fd4b1acb7cb70728
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = ByPassFireWall[zip]/Folder.Inject
    threattype = zip
  strings:
    $s6 = "Fail To Inject" fullword ascii
    $s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
    $s11 = " Successfully" fullword ascii
  condition:
    all of them
}