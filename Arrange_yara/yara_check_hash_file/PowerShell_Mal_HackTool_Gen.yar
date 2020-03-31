rule PowerShell_Mal_HackTool_Gen {
  meta:
    author = Spider
    comment = None
    date = 2017-11-02
    description = Detects PowerShell hack tool samples - generic PE loader
    family = Gen
    hacker = None
    hash1 = d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research
    threatname = PowerShell[Mal]/HackTool.Gen
    threattype = Mal
  strings:
    $x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA" wide
    $x2 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword wide
    $x3 = "@($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword wide
    $x4 = "(Shellcode: LoadLibraryA.asm)" fullword wide
  condition:
    filesize < 8000KB and 1 of them
}