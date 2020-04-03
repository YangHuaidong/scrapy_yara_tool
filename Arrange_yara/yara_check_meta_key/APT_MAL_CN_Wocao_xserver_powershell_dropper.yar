rule APT_MAL_CN_Wocao_xserver_powershell_dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from the PowerShell dropper of XServer"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $encfile = "New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($encfile)"
  condition:
    all of them
}