# SQL injection detector

This package proporcionates the capability of detecting sql injection in your json/dict data.
Regardles of how your data looks like and how nested is your dictionary, it will go through 
each step and provide a response

Usage:

import libs

```python 
from sqlinjection.sql_injection import SqlInjectionChecker
from sqlinjection.errors import SqlInjectionException
```

for validating a dictionary

```python 
try:
    SqlInjectionChecker().validate_json(data)
except SqlInjectionException as exc:
    # if an sql injection has been detected an exception will be raised
    print(exc)
```