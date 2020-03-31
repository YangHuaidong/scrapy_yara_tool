# -*-coding:utf-8 -*-
import os
import re
import yaratool

curie = os.path.dirname(os.path.realpath(__file__))

CVE_Rules_file = os.path.join(curie, "CVE_Rules_file")
CVE_Rules_file_new = os.path.join(curie, "CVE_Rules_file_new")
# filepath = "/home/kevin/rules/Arrange_yara/CVE_Rules_file/3_Exploit_MS15_077_078_HackingTeam:.yar"

Webshells_file = os.path.join(curie, "Webshells_file")
Webshells_file_new = os.path.join(curie, "Webshells_file_new")

Exploit_Kits_file = os.path.join(curie, "Exploit_Kits_file")
Exploit_Kits_file_new = os.path.join(curie, "Exploit_Kits_file_new")

Capabilities_file = os.path.join(curie, "Capabilities_file")
Capabilities_file_new = os.path.join(curie, "Capabilities_file_new")


def check_meta_key(file, file_new, threattype =''):
    for rootpath, dirpath, filenames in os.walk(file):
        for filename in filenames:
            filepath = os.path.join(rootpath, filename)
            with open(filepath, 'rb')as f:
                f.seek(0)
                rules = f.read()
            try:
                yr = yaratool.YaraRule(rules)
            except Exception as e:
                print('YaraRule cannot parse the rule!')
            else:
                try:
                    if not yr.strings:
                        print ("not yara_strings")
                    if not yr.conditions:
                        print ("not yara_condition")
                except Exception as e:
                    print ('Condition not satisfied analysis!')
                else:
                    if "judge" not in yr.metas.keys():
                        yr.metas['judge'] = 'None'
                    if "threatname" not in yr.metas.keys():
                        yr.metas['threatname'] = 'None'
                    if "threattype" not in yr.metas.keys():
                        yr.metas['threattype'] = 'None'
                    if "family" not in yr.metas.keys():
                        yr.metas['family'] = 'None'
                    if "hacker" not in yr.metas.keys():
                        yr.metas['hacker'] = 'None'
                    if "comment" not in yr.metas.keys():
                        yr.metas['comment'] = 'None'
                    if "date" not in yr.metas.keys():
                        yr.metas['date'] = 'None'
                    if "reference" not in yr.metas.keys():
                        yr.metas['reference'] = 'None'
                    if "description" not in yr.metas.keys():
                        yr.metas['description'] = 'None'

                    yr.metas['author'] = 'Spider'
                    yr.metas['threattype'] = threattype
                    for key in yr.metas.keys():
                        if key not in ["judge", "threatname", "threattype", "family", "hacker",
                                       "comment", "date", "author", "reference", "description"]:
                            yr.metas.pop(key)
                            new_rule = yr.normalize()
                            tatol = re.search(r'rule.*', new_rule).group()
                            tatol1 = tatol.split()
                            rule_name = os.path.join(file_new, tatol1[1]+".yar")
                            yr.metas['threatname'] = tatol1[1].replace("_",".")
                            new_rule1 = yr.normalize()
                            with open(rule_name, 'w+')as tmp:
                                tmp.write(new_rule1)



if __name__ == '__main__':

    # check_meta_key(CVE_Rules_file,CVE_Rules_file_new,'CVE')
    check_meta_key(Webshells_file,Webshells_file_new,'Webshells')
    # check_meta_key(Exploit_Kits_file,Exploit_Kits_file_new,"Exploit")
    # check_meta_key(Capabilities_file, Capabilities_file_new,'Capabilities')
