rule svchostdll {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file svchostdll.dll"
    family = "None"
    hacker = "None"
    hash = "0f6756c8cb0b454c452055f189e4c3f4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "InstallService"
    $s1 = "RundllInstallA"
    $s2 = "UninstallService"
    $s3 = "&G3 Users In RegistryD"
    $s4 = "OL_SHUTDOWN;I"
    $s5 = "SvcHostDLL.dll"
    $s6 = "RundllUninstallA"
    $s7 = "InternetOpenA"
    $s8 = "Check Cloneomplete"
  condition:
    all of them
}