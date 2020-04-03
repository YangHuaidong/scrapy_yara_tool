rule RkNTLoad {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file RkNTLoad.exe"
    family = "None"
    hacker = "None"
    hash = "262317c95ced56224f136ba532b8b34f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
    $s2 = "5pur+virtu!"
    $s3 = "ugh spac#n"
    $s4 = "xcEx3WriL4"
    $s5 = "runtime error"
    $s6 = "loseHWait.Sr."
    $s7 = "essageBoxAw"
    $s8 = "$Id: UPX 1.07 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $"
  condition:
    all of them
}