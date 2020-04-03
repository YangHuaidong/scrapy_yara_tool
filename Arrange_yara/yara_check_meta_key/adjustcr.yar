rule adjustcr {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file adjustcr.exe"
    family = "None"
    hacker = "None"
    hash = "17037fa684ef4c90a25ec5674dac2eb6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$Info: This file is packed with the UPX executable packer $"
    $s2 = "$License: NRV for UPX is distributed under special license $"
    $s6 = "AdjustCR Carr"
    $s7 = "ION\\System\\FloatingPo"
  condition:
    all of them
}