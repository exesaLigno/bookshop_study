import atheris
import sys
from random import choice
with atheris.instrument_imports():
    from eshop import Shop

commands = [
    'вход', 'выход', 'каталог', 'добавить_товар', 'корзина', 
    'добавить_в_корзину', 'очистить_корзину', 'доставить', 'заказы', 
    'вернуть_заказ', 'все_заказы', 'подтвердить_доставку', 'все_возвраты', 
    'одобрить_возврат', 'сделать_бочку', 'отклонить_доставку', 'фыва',
    'биба', 'боба'
    ]

errors = []

def generate_input(input_bytes):
    cmd = choice(commands)
    try:
        fdp = atheris.FuzzedDataProvider(input_bytes)
        data = list(fdp.ConsumeUnicode(sys.maxsize).split())
    except UnicodeEncodeError:
        data = []
    inp = [cmd] + data
    empty_count = inp.count('')
    for _ in range(empty_count):
        inp.remove('')
    return ' '.join(inp)
    

def test_fuzz(input_bytes):
    try:
        data = generate_input(input_bytes)
        shop = Shop()
        result = shop.process(data)
    except Exception as error:
        errors.append(error)

if __name__ == "__main__":
    atheris.Setup(sys.argv, test_fuzz)
    atheris.Fuzz()
    print(len(errors))
