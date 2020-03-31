rule ROKRAT_Dropper_Nov17 {
   meta:
      description = "Detects dropper for ROKRAT malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      hash1 = "eb6d25e08b2b32a736b57f8df22db6d03dc82f16da554f4e8bb67120eacb1d14"
      hash2 = "a29b07a6fe5d7ce3147dd7ef1d7d18df16e347f37282c43139d53cce25ae7037"
   condition:
      uint16(0) == 0x5a4d and filesize < 2500KB and
      pe.imphash() == "c6187b1b5f4433318748457719dd6f39"
}