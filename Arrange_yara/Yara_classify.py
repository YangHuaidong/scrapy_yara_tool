# -*-coding:utf8 -*-
# auther : yanghuaidong
# date : 2019/09/18

import os

import yaratool

hash_file = "/home/kevin/Desktop/Arrange_yara/hash_file"

curdir = os.path.dirname(os.path.realpath(__file__))
yara = os.path.join(curdir, "yara")
yara_check_file = os.path.join(curdir, "yara_check_file")
yara_check_meta_key = os.path.join(curdir, "yara_check_meta_key")
yara_check_meta_key_hash = os.path.join(curdir, "yara_check_meta_key_hash")


class Yara_Check_Rules():
    """封装yaratool"""

    def __init__(self):
        pass

    def yara_open_file(self, file_path):
        try:
            for rootpath, dirpath, filenames in os.walk(file_path):
                for filename in filenames:
                    filepath = os.path.join(rootpath, filename)
                    with open(filepath, 'r')as f:
                        f.seek(0)
                        rules = f.read()
                        yield [filename, rules]
        except Exception as e:
            pass

    def yara_classify(self, file_path, yara_check_file):
        """yara分类/有带pe包和没有带的分开"""
        try:
            for rules in self.yara_open_file(file_path):
                if not isinstance(rules, list):
                    continue
                if rules[1].find('rule') != -1:
                    try:
                        sigrules = yaratool.split(rules[1])
                    except Exception as e:
                        continue
                    for rule in sigrules:
                        rule_name = os.path.join(yara_check_file, rule.name) + ".yar"
                        with open(rule_name, 'w')as tmp:
                            tmp.write(rule.original)

        except Exception as e:
            pass

    def yara_meta_key(self, yara_check_file, yara_check_meta_key):
        """yarameta格式效验"""
        try:
            for rules in self.yara_open_file(yara_check_file):
                if not isinstance(rules, list):
                    continue
                try:
                    yr = yaratool.YaraRule(rules[1])
                except Exception as e:
                    continue
                if "judge" not in yr.metas.keys():
                    yr.metas['judge'] = "black"
                if "threatname" not in yr.metas.keys():
                    yr.metas['threatname'] = "None"
                if "threattype" not in yr.metas.keys():
                    yr.metas['threattype'] = "None"
                if "family" not in yr.metas.keys():
                    yr.metas['family'] = "None"
                if "hacker" not in yr.metas.keys():
                    yr.metas['hacker'] = "None"
                if "comment" not in yr.metas.keys():
                    yr.metas['comment'] = "None"
                if "date" not in yr.metas.keys():
                    yr.metas['date'] = "None"
                if "reference" not in yr.metas.keys():
                    yr.metas['reference'] = "None"
                if "description" not in yr.metas.keys():
                    yr.metas['description'] = "None"
                yr.metas['author'] = "Spider"
                try:
                    yara_new = yr.normalize()
                    rule_name = os.path.join(yara_check_meta_key, rules[0])
                    res = "".join(yr.conditions)
                    if not "pe." in res:
                        with open(rule_name, 'w')as tmp:
                            tmp.write(yara_new)
                    else:
                        with open(rule_name, 'w')as tmp1:
                            tmp1.write("import \"pe\"\n\r" + yara_new)
                except Exception as e:
                    pass
        except Exception as e:
            print(e)

    def yara_meta_hash(self, yara_check_meta_key, yara_check_meta_key_hash):
        try:
            for rules in self.yara_open_file(yara_check_meta_key):
                if not isinstance(rules, list):
                    continue
                try:
                    yr = yaratool.YaraRule(rules[1])
                except Exception as e:
                    print(e)
                else:
                    for k in ["hash", "hash1"]:
                        if k in yr.metas.keys():
                            rule_name = os.path.join(yara_check_meta_key_hash, yr.name)
                            try:
                                with open(rule_name, 'w')as tmp:
                                    tmp.write(rules[1])
                                with open(hash_file, "a")as n:
                                    n.write(yr.metas[k] + "\n")
                            except Exception as e:
                                print(e)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    a = Yara_Check_Rules()
    # a.yara_classify(yara, yara_check_file)
    a.yara_meta_key(yara_check_file, yara_check_meta_key)
    # a.yara_meta_hash(yara_check_meta_key, yara_check_meta_key_hash)
    # pass
