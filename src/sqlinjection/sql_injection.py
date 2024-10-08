import re
import copy

from .errors import SqlInjectionException


class SqlInjectionChecker:

    definitions = {
        'select': r'(select|s\/\*\*\/elect|se\/\*\*\/lect|sel\/\*\*\/ect|sele\/\*\*\/ct|selec\/\*\*\/t)\s.*(from|f\/\*\*\/rom|fr\/\*\*\/om|fro\/\*\*\/m)',
        'insert': r'(insert|i\/\*\*\/nsert|in\/\*\*\/sert|ins\/\*\*\/ert|inse\/\*\*\/rt|inser\/\*\*\/t)\s.*(into|i\/\*\*\/nto|in\/\*\*\/to|int\/\*\*\/o)',
        'case': r'(select|s\/\*\*\/elect|se\/\*\*\/lect|sel\/\*\*\/ect|sele\/\*\*\/ct|selec\/\*\*\/t)\s.*(case|c\/\*\*\/ase|ca\/\*\*\/se|cas\/\*\*\/e)',
        'delete': r'(delete|d\/\*\*\/elete|de\/\*\*\/lete|del\/\*\*\/ete|dele\/\*\*\/te|delet\/\*\*\/e)\s.*(from|f\/\*\*\/rom|fr\/\*\*\/om|fro\/\*\*\/m)',
        'drop': r'(drop|d\/\*\*\/rop|dr\/\*\*\/op|dro\/\*\*\/p)\s.*' +
                r'(table|t\/\*\*\/able|ta\/\*\*\/ble|tab\/\*\*\/le|tabl\/\*\*\/e' +
                r'|function|f\/\*\*\/unction|fu\/\*\*\/nction|fun\/\*\*\/ction|func\/\*\*\/tion|funct\/\*\*\/ion|functi\/\*\*\/on|functio\/\*\*\/n' +
                r'|index|i\/\*\*\/ndex|in\/\*\*\/dex|ind\/\*\*\/ex|inde\/\*\*\/x' +
                r'|procedure|p\/\*\*\/rocedure|pr\/\*\*\/ocedure|pro\/\*\*\/cedure|proc\/\*\*\/edure|proce\/\*\*\/dure|proced\/\*\*\/ure|procedu\/\*\*\/re|procedur\/\*\*\/e' +
                r'|role|r\/\*\*\/ole|ro\/\*\*\/le|rol\/\*\*\/e|schema|s\/\*\*\/chema|sc\/\*\*\/hema|sch\/\*\*\/ema|sche\/\*\*\/ma|schem\/\*\*\/a ' +
                r'|sequence|s\/\*\*\/equence|se\/\*\*\/quence|seq\/\*\*\/uence|sequ\/\*\*\/ence|seque\/\*\*\/nce|seque\/\*\*\/nce|sequen\/\*\*\/ce|sequenc\/\*\*\/e' +
                r'|synonym|s\/\*\*\/ynonym|sy\/\*\*\/nonym|syn\/\*\*\/onym|syno\/\*\*\/nym|synon\/\*\*\/ym|synon\/\*\*\/ym|synony\/\*\*\/m' +
                r'|trigger|t\/\*\*\/rigger|tr\/\*\*\/igger|tri\/\*\*\/gger|trig\/\*\*\/ger|trigg\/\*\*\/er|trigge\/\*\*\/r' +
                r'|type|t\/\*\*\/ype|ty\/\*\*\/pe|typ\/\*\*\/e|view|v\/\*\*\/iew|vi\/\*\*\/ew|vie\/\*\*\/w' +
                r'|user|u\/\*\*\/ser|us\/\*\*\/er|use\/\*\*\/r)', # see https://docs.oracle.com/javadb/10.8.3.0/ref/crefsqlj80721.html
        'truncate': r'(truncate|t\/\*\*\/runcate|tr\/\*\*\/uncate|tru\/\*\*\/ncate|trun\/\*\*\/cate|trunc\/\*\*\/ate|trunca\/\*\*\/te|truncat\/\*\*\/e)\s.*(table' +
                r'|t\/\*\*\/able|ta\/\*\*\/ble|tab\/\*\*\/le|tabl\/\*\*\/e' +
                r'|cluster|c\/\*\*\/luster|cl\/\*\*\/uster|clu\/\*\*\/ster|clus\/\*\*\/ter|clust\/\*\*\/er|cluste\/\*\*\/r)',
        'alter': r'(alter|a\/\*\*\/lter|al\/\*\*\/ter|alt\/\*\*\/er|alte\/\*\*\/r)\s.*(table|t\/\*\*\/able|ta\/\*\*\/ble|tab\/\*\*\/le|tabl\/\*\*\/e' +
                r'|user|u\/\*\*\/ser|us\/\*\*\/er|use\/\*\*\/r)',
        'update': r'(update|u\/\*\*\/pdate|up\/\*\*\/date|upd\/\*\*\/ate|upda\/\*\*\/te|updat\/\*\*\/e)\s.*(' +
                r'from|f\/\*\*\/rom|fr\/\*\*\/om|fro\/\*\*\/m)',
        'into': r'(select|s\/\*\*\/elect|se\/\*\*\/lect|sel\/\*\*\/ect|sele\/\*\*\/ct|selec\/\*\*\/t' +
                r'|merge|m\/\*\*\/erge|me\/\*\*\/rge|mer\/\*\*\/ge|merg\/\*\*\/e)\s.*(into|i\/\*\*\/nto|in\/\*\*\/to|int\/\*\*\/o)',
        'execute': r'(exec|e\/\*\*\/xec|ex\/\*\*\/ec|exe\/\*\*\/c|execute|e\/\*\*\/xecute|ex\/\*\*\/ecute|exe\/\*\*\/cute' +
                r'|execu\/\*\*\/te|execut\/\*\*\/e)\s.*(inmediate|i\/\*\*\/nmediate|inm\/\*\*\/ediate|inme\/\*\*\/diate|inmed\/\*\*\/iate|inmedi\/\*\*\/ate' +
                r'|inmedia\/\*\*\/te|inmediat\/\*\*\/e)',
        'declare': r'(declare|d\/\*\*\/eclare|de\/\*\*\/clare|dec\/\*\*\/lare|decl\/\*\*\/are|decla\/\*\*\/re|declar\/\*\*\/e)\s.*(' +
                r'begin|b\/\*\*\/egin|be\/\*\*\/gin|beg\/\*\*\/in|begi\/\*\*\/n|end|e\/\*\*\/nd|en\/\*\*\/d)',
        'begin': r'(begin|b\/\*\*\/egin|be\/\*\*\/gin|beg\/\*\*\/in|begi\/\*\*\/n)\s.*(end|e\/\*\*\/nd|en\/\*\*\/d)',
        'syscontext': r'(sys_context|s\/\*\*\/ys_context|sy\/\*\*\/s_context|sys\/\*\*\/_context|sys_\/\*\*\/context)',
        'describe': r'(describe|d\/\*\*\/escribe|des\/\*\*\/cribe|desc\/\*\*\/ribe|descr\/\*\*\/ibe|descri\/\*\*\/be|describ\/\*\*\/e' +
                r'|desc|d\/\*\*\/esc|de\/\*\*\/sc|des\/\*\*\/c)\s.*(table|t\/\*\*\/able|ta\/\*\*\/ble|tab\/\*\*\/le|tabl\/\*\*\/e)'
    }

    def __init__(self):
        pass

    @classmethod
    def __pattern_checker(cls, value: str) -> bool:
        """
        Checks the value for sql injection
        Args:
            value (str): value to be checked
        Returns:
            (bool) check result
        """
        for pattern in cls.definitions:
            if re.search(cls.definitions[pattern], value.lower()):
                return True
        return False

    @classmethod
    def validate_json(cls, data: dict) -> bool:
        """
        json validation through sql injections test
        Args:
            data (dict): dictionary to be checked
        Returns:
            (bool): result of dict check
        """
        data = copy.deepcopy(data)
        for key in data:
            if isinstance(data[key], dict):
                if data[key] == {}:
                    data.pop(key)
                else:
                    cls.validate_json(data=data[key])
            elif isinstance(data[key], str):
                if cls.__pattern_checker(value=data[key]):
                    raise SqlInjectionException(
                        message='sql injection found',
                        key=key,
                        value=data[key])
                data.pop(key)
                return cls.validate_json(data=data)
            elif isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, str):
                        if cls.__pattern_checker(value=item):
                            raise SqlInjectionException(
                                message='sql injection found',
                                key=key,
                                value=item)
                data.pop(key)
                return cls.validate_json(data=data)
            else:
                data.pop(key)
                return cls.validate_json(data=data)
        return True

    @classmethod
    def validate_string(cls, value: str) -> bool:
        """
        string validation through sql injections test
        Args:
            value (str): dictionary to be checked
        Returns:
            (bool): result of dict check
        """
        return cls.__pattern_checker(value=value)

    @classmethod
    def validate_list(cls, item_list: list) -> bool:
        """
        list validation through sql injections test
        Args:
            item_list (list): dictionary to be checked
        Returns:
            (bool): result of dict check
        """
        for item in item_list:
            if cls.validate_string(item):
                return True
        return False
