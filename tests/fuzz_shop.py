import atheris
import sys
from eshop import Shop

def test_fuzz(input_bytes):
    try:
        fdp = atheris.FuzzedDataProvider(input_bytes)
        data = fdp.ConsumeUnicode(sys.maxsize)
        shop = Shop()
        result = shop.process(data)
        # print(f'Input: {data}')
        # print(f'Result: {result}')
    except (UnicodeEncodeError, IndexError):
        pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, test_fuzz)
    atheris.Fuzz()
