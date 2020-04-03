rule Prikormka {
  meta:
    Author = "Anton Cherepanov"
    Contact = "threatintel@eset.com"
    Date = "2016/05/10"
    Description = "Operation Groundbait"
    License = "BSD 2-Clause"
    Source = "https://github.com/eset/malware-ioc/"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  condition:
    PrikormkaDropper or PrikormkaModule or PrikormkaEarlyVersion
}