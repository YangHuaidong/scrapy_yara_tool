rule skeleton_key_patcher {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/01/13"
    description = "Skeleton Key Patcher from Dell SecureWorks Report http://goo.gl/aAk3lN"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/aAk3lN"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $target_process = "lsass.exe" wide
    $dll1 = "cryptdll.dll"
    $dll2 = "samsrv.dll"
    $name = "HookDC.dll"
    $patched1 = "CDLocateCSystem"
    $patched2 = "SamIRetrievePrimaryCredentials"
    $patched3 = "SamIRetrieveMultiplePrimaryCredentials"
  condition:
    all of them
}