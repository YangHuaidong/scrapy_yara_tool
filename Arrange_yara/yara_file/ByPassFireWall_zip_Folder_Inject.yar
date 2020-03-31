rule ByPassFireWall_zip_Folder_Inject {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Inject.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
   strings:
      $s6 = "Fail To Inject" fullword ascii
      $s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
      $s11 = " Successfully" fullword ascii
   condition:
      all of them
}