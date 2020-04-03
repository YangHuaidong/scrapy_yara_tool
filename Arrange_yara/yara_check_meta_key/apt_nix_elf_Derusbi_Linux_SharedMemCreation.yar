rule apt_nix_elf_Derusbi_Linux_SharedMemCreation {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/02/29"
    description = "Detects Derusbi Backdoor ELF Shared Memory Creation"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
    threatname = "None"
    threattype = "None"
  strings:
    $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }
  condition:
    uint32(0) == 0x464C457F and any of them
}