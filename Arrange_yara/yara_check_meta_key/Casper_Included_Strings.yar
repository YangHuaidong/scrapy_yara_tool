rule Casper_Included_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/06"
    description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/VRJNLo"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
    $a1 = "& SYSTEMINFO) ELSE EXIT"
    $c1 = "domcommon.exe" wide fullword							// File Name
    $c2 = "jpic.gov.sy" fullword 								// C2 Server
    $c3 = "aiomgr.exe" wide fullword							// File Name
    $c4 = "perfaudio.dat" fullword								// Temp File Name
    $c5 = "Casper_DLL.dll" fullword								// Name
    $c6 = { 7b 4b 59 de 37 4a 42 26 59 98 63 c6 2d 0f 57 40 } 	// Decryption Key
    $c7 = "{4216567A-4512-9825-7745F856}" fullword 				// Mutex
  condition:
    all of ($a*) or
    uint16(0) == 0x5a4d and ( 1 of ($c*) )
}