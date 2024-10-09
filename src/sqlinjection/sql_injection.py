import re
import copy

from .errors import SqlInjectionException


class SqlInjectionChecker:

    definitions = {
        'select': r'(select)\s.*(from)',
        'insert': r'(insert)\s.*(into)',
        'case': r'(select)\s.*(case)',
        'delete': r'(delete)\s.*(from)',
        'drop': r'(drop)\s.*(table|function|index|procedure|role|schema|sequence|synonym|trigger|type|view|user)',
        'truncate': r'(truncate)\s.*(table|cluster)',
        'alter': r'(alter)\s.*(table|user)',
        'update': r'(update)\s.*(from)',
        'into': r'(select|merge)\s.*(into)',
        'execute': r'(exec||execute)\s.*(inmediate)',
        'declare': r'(declare)\s.*(begin|end|)',
        'begin': r'(begin)\s.*(end)',
        'syscontext': r'sys_context',
        'describe': r'(describe|desc|)\s.*(table)'
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
        value = re.sub(r'\/\*.*?\/','', value)
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
