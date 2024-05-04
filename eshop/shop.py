#!/usr/bin/python
from typing import Callable
from dataclasses import dataclass

@dataclass
class Book:
    title: str
    author: str
    issue_year: int
    price: float
    publisher: str
    genre: str

class Cart:

    carts_counter = 0
    
    def __init__(self, buyer_login: str):
        self.buyer_login: str = buyer_login
        self.shop_list: list[Book] = []
        self.pk: int = self.carts_counter
        self.carts_counter += 1
        self.delivery: bool = False
        self.delivery_adress: str | None = None
        self.delivery_time: str | None = None
        self.payment_method: str | None = None
    
    def add_book_to_cart(self, book: Book) -> None:
        self.shop_list.append(book)

    def deliver(self, delivery_adress: str, delivery_time: str, payment_method: str):
        self.delivery = True
        self.delivery_adress = delivery_adress
        self.delivery_time = delivery_time
        self.payment_method = payment_method

class Shop:

    handlers: dict[str, str] = {
        'вход': 'login',
        'выход': 'unlogin',
        'каталог': 'catalog',
        'добавить_товар': 'add_book',
        'корзина': 'show_cart',
        'добавить_в_корзину': 'add_book_to_cart',
        'доставить': 'deliver',
        'очистить_корзину': 'clear_cart',
        'заказы': 'orders'
    }

    @classmethod
    def __split_command_line(cls, command_line: str) -> list[str]:
        splitted = []
        command_line = command_line.replace('\'', '\"')
        splitted_by_quotes = command_line.split('\"')
        for i, part in enumerate(splitted_by_quotes):
            if i % 2 == 0:
                splitted += part.strip().split()
            else:
                splitted.append(part.strip())
        return splitted

    def __init__(self):
        self.users: dict[str, bool] = {}
        self.current_user: str | None = None
        self.books_catalog: list[Book] = []
        self.carts: list[Cart] = []

    def process(self, command_line: str) -> str:
        splitted = self.__split_command_line(command_line)
        cmd, args = splitted[0], splitted[1:]
        return self.process_internal(cmd, args)

    def process_internal(self, cmd: str, args: list[str]) -> str:
        handler = lambda _: f'Команда {cmd} не поддерживается'
        if cmd in self.handlers:
            handler = getattr(self, self.handlers[cmd])
        
        return handler(args)

    def register_user(self, login: str, moderator: bool = False) -> None:
        '''
        This method designed for user creation
        It isn't callable from cli
        '''
        self.users[login] = moderator

    def login(self, args: list[str]) -> str:
        message = f'Пользователь с логином {args[0]} не зарегестрирован!'
        if args[0] in self.users:
            message = f'Добро пожаловать, {args[0]}!'
            if self.users[args[0]]:
                message += ' Вы являетесь администратором!'
            self.current_user = args[0]
        return message

    def unlogin(self, args: list[str]) -> str:
        message = 'Вы не авторизованы!'
        if self.current_user is not None:
            message = f'До свидания, {self.current_user}!'
            self.current_user = None
        return message

    def catalog(self, args: list[str]) -> str:
        message = 'Каталог пуст!'
        if len(self.books_catalog) != 0:
            message = 'Каталог:'
            for book in self.books_catalog:
                message += f'\n\t{book.title} ({book.author}) --- {book.price}'
        return message

    def add_book(self, args: list[str]) -> str:
        new_book = Book(args[0], args[1], int(args[2]), float(args[3]), args[4], args[5])
        self.books_catalog.append(new_book)
        return f'Книга "{new_book.title}" добавлена в каталог!'

    def show_cart(self, args: list[str]) -> str:
        message = 'Ваша корзина пока пуста.'
        user_carts = list(filter(lambda cart: cart.buyer_login == self.current_user and not cart.delivery, self.carts))
        if len(user_carts) != 0 and len(user_carts[0].shop_list) != 0:
            message = 'Ваша корзина:'
            for book in user_carts[0].shop_list:
                message += f'\n\t{book.title} ({book.author}) --- {book.price}'
        return message

    def add_book_to_cart(self, args: list[str]) -> str:
        user_carts = list(filter(lambda cart: cart.buyer_login == self.current_user and not cart.delivery, self.carts))
        if len(user_carts) == 0:
            new_cart = Cart(self.current_user)
            self.carts.append(new_cart)
            cart = new_cart
        else:
            cart = user_carts[0]
        
        suggested_books = list(filter(lambda book: book.title.lower() == args[0].lower(), self.books_catalog))
        if len(suggested_books) != 0:
            cart.add_book_to_cart(suggested_books[0])
            message = f'Книга "{suggested_books[0].title}" добавлена в вашу корзину.'
        
        return message

    def deliver(self, args: list[str]) -> str:
        user_carts = list(filter(lambda cart: cart.buyer_login == self.current_user and not cart.delivery, self.carts))
        if len(user_carts) == 0:
            new_cart = Cart(self.current_user)
            self.carts.append(new_cart)
            cart = new_cart
        else:
            cart = user_carts[0]

        cart.deliver(args[0], args[1], args[2])

        return f'Доставка оформлена, заказ #{cart.pk}'

    def clear_cart(self, args: list[str]) -> str:
        user_carts = list(filter(lambda cart: cart.buyer_login == self.current_user and not cart.delivery, self.carts))
        if len(user_carts) == 0:
            new_cart = Cart(self.current_user)
            self.carts.append(new_cart)
            cart = new_cart
        else:
            cart = user_carts[0]

        cart.shop_list = []
        return 'Ваша корзина очищена.'

    def orders(self, args: list[str]) -> str:
        orders = list(filter(lambda cart: cart.buyer_login == self.current_user and cart.delivery, self.carts))
        if len(orders) == 0:
            return 'У вас нет активных заказов.'
        else:
            pass
