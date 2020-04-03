rule REDLEAVES_DroppedFile_ImplantLoader_Starburn {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detect the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
    threatname = "None"
    threattype = "None"
    true_positive = "7f8a867a8302fe58039a6db254d335ae" // StarBurn.dll"
  strings:
    $XOR_Loop = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10} // Deobfuscation loop
  condition:
    any of them
}