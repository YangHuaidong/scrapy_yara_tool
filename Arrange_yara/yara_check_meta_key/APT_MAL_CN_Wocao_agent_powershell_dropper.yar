rule APT_MAL_CN_Wocao_agent_powershell_dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from PowerShell dropper of CSharp version of Agent"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "function format([string]$source)"
    $b = "foreach($c in $bb){$tt = $tt + [char]($c -bxor"
    $c = "[agent]::Main($args);"
  condition:
    1 of them
}