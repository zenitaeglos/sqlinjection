

class SqlInjectionException(Exception):
    """
    Custom Sql Injection Exception
    Args:
        message (str): error exception message
        key (str): for json/dict key where the exception is found
        value (str): value with the data
        description (str): exception description
    """
    def __init__(self, 
    message: str, 
    key: str = None,
    value: str = None,
    description: str = None):
        super().__init__(message)
        self.message = message
        self.key = key
        self.value = value
        self.description = description

    def __str__(self):
        return f'{self.message}, found in key: {self.key}, offending value: {self.value}'