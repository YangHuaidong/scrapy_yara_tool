rule _Bitchin_Threads_ {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file =Bitchin Threads=.exe"
    family = "None"
    hacker = "None"
    hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "DarKPaiN"
    $s1 = "=BITCHIN THREADS"
  condition:
    all of them
}