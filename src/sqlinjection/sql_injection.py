import re
import copy

from .errors import SqlInjectionException


class SqlInjectionChecker:

    definitions = {
        'select': '(select).*(from)',
        'case': '(select).*(case)',
        'create': '(create).*(table)',
        'delete': '(delete).*(from)',
        'drop': '(drop).*(table)',
        'insert': '(insert).*(into)',
        'alter': '(alter).*(table)'
    }

    def __init__(self):
        pass

    @classmethod
    def __pattern_checker(self, value: str) -> bool:
        """
        Checks the value for sql injection
        Args:
            value (str): value to be checked
        Returns:
            (bool) check result
        """
        for pattern in self.definitions:
            if re.search(self.definitions[pattern], value.lower()):
                return True

        return False

    @classmethod
    def validate_json(self, data: dict) -> bool:
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
                    self.validate_json(data=data[key])
            elif isinstance(data[key], str):
                if self.__pattern_checker(value=data[key]):
                    raise SqlInjectionException(
                        message='sql injection found',
                        key=key,
                        value=data[key])
                data.pop(key)
                return self.validate_json(data=data)
            elif isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, str):
                        if self.__pattern_checker(value=item):
                            raise SqlInjectionException(
                                message='sql injection found',
                                key=key,
                                value=item)
                data.pop(key)
                return self.validate_json(data=data)
            else:
                data.pop(key)
                return self.validate_json(data=data)
        return True

    @classmethod
    def validate_string(self, value: str) -> bool:
        """
        string validation through sql injections test
        Args:
            value (str): dictionary to be checked
        Returns:
            (bool): result of dict check
        """
        return self.__pattern_checker(value=value)

    @classmethod
    def validate_list(self, item_list: list) -> bool:
        """
        list validation through sql injections test
        Args:
            item_list (list): dictionary to be checked
        Returns:
            (bool): result of dict check
        """
        for item in item_list:
            if self.validate_string(item):
                return True
        return False