rule KeeTheft_EXE {
  meta:
    author = Spider
    comment = None
    date = 2017-08-29
    description = Detects component of KeeTheft - KeePass dump tool - file KeeTheft.exe
    family = None
    hacker = None
    hash1 = f06789c3e9fe93c165889799608e59dda6b10331b931601c2b5ae06ede41dc22
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/HarmJ0y/KeeThief
    threatname = KeeTheft[EXE
    threattype = EXE.yar
  strings:
    $x1 = "Error: Could not create a thread for the shellcode" fullword wide
    $x2 = "Could not find address marker in shellcode" fullword wide
    $x3 = "GenerateDecryptionShellCode" fullword ascii
    $x4 = "KeePassLib.Keys.KcpPassword" fullword wide
    $x5 = "************ Found a CompositeKey! **********" fullword wide
    $x6 = "*** Interesting... there are multiple .NET runtimes loaded in KeePass" fullword wide
    $x7 = "GetKcpPasswordInfo" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}