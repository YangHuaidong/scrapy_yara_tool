rule Reflective_DLL_Loader_Aug17_3 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "d10e4b3f1d00f4da391ac03872204dc6551d867684e0af2a4ef52055e771f474"
   strings:
      $s1 = "\\Release\\inject.pdb" fullword ascii
      $s2 = "!!! Failed to gather information on system processes! " fullword ascii
      $s3 = "reflective_dll.dll" fullword ascii
      $s4 = "[-] %s. Error=%d" fullword ascii
      $s5 = "\\Start Menu\\Programs\\reflective_dll.dll" ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
           pe.imphash() == "26ba48d3e3b964f75ff148b6679b42ec" or
           2 of them
        )
      ) or ( 3 of them )
}