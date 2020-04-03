rule Empire_lib_modules_trollsploit_message {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
    family = "None"
    hacker = "None"
    hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/PowerShellEmpire/Empire"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii
    $s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii
    $s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii
    $s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii
  condition:
    filesize < 10KB and 3 of them
}