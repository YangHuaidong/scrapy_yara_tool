rule SeDLL_Javascript_Decryptor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-18"
    description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
    family = "None"
    hacker = "None"
    hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/MZ7dRg"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "SEDll_Win32.dll" fullword ascii
    $x2 = "regsvr32 /s \"%s\" DR __CIM__" fullword wide
    $s1 = "WScriptW" fullword ascii
    $s2 = "IWScript" fullword ascii
    $s3 = "%s\\%s~%d" fullword wide
    $s4 = "PutBlockToFileWW" fullword ascii
    $s5 = "CheckUpAndDownWW" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($x*) or 4 of them )
}