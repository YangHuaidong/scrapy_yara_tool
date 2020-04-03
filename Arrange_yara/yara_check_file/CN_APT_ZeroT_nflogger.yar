rule CN_APT_ZeroT_nflogger {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT  - file nflogger.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04"
      hash1 = "946adbeb017616d56193a6d43fe9c583be6ad1c7f6a22bab7df9db42e6e8ab10"
   strings:
      $x1 = "\\LoaderDll.VS2010\\Release\\" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}