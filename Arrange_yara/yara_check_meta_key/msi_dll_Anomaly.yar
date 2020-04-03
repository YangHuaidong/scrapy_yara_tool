rule msi_dll_Anomaly {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Detetcs very small and supicious msi.dll"
    family = "None"
    hacker = "None"
    hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "msi.dll.eng" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 15KB and filename == "msi.dll" and $x1
}