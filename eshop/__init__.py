'''Shop module'''
from dataclasses import dataclass


@dataclass
class Book:
    '''Book representation'''
    title: str
    author: str
    issue_year: int
    price: float
    publisher: str
    genre: str


class Cart:
    '''Cart representation'''
    def __init__(self, buyer_login: str, cart_id: int):
        '''Initializer of cart'''
        self.buyer_login: str = buyer_login
        self.shop_list: list[Book] = []
        self.primary_key: int = cart_id
        self.delivery: bool = False
        self.delivery_adress: str | None = None
        self.delivery_time: str | None = None
        self.payment_method: str | None = None

    def add_book_to_cart(self, book: Book) -> None:
        '''Method for adding new book to cart'''
        self.shop_list.append(book)

    def deliver(self, delivery_adress: str,
                delivery_time: str, payment_method: str) -> None:
        '''Deliver cart contents'''
        self.delivery = True
        self.delivery_adress = delivery_adress
        self.delivery_time = delivery_time
        self.payment_method = payment_method


class Shop:
    '''Shop class'''

    handlers: dict[str, str] = {
        'вход': 'login',
        'выход': 'unlogin',
        'каталог': 'catalog',
        'добавить_товар': 'add_book',
        'корзина': 'show_cart',
        'добавить_в_корзину': 'add_book_to_cart',
        'очистить_корзину': 'clear_cart',
        'доставить': 'deliver',
        'заказы': 'orders',
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

    def __init__(self) -> None:
        '''Initialize shop object'''
        self.users: dict[str, bool] = {}
        self.current_user: str | None = None
        self.books_catalog: list[Book] = []
        self.carts_counter: int = 0
        self.carts: list[Cart] = []

    def process(self, command_line: str) -> str:
        '''Processor for external command line'''
        splitted = self.__split_command_line(command_line)
        cmd, args = splitted[0], splitted[1:]
        return self.process_internal(cmd, args)

    def process_internal(self, cmd: str, args: list[str]) -> str:
        '''Internal parser'''
        message = f'Команда {cmd} не поддерживается'
        if cmd in self.handlers:
            handler = getattr(self, self.handlers[cmd])
            message = handler(args)

        return message

    def register_user(self, login: str, moderator: bool = False) -> None:
        '''This method designed for user creation. It isnt callable from cli'''
        self.users[login] = moderator

    def login(self, args: list[str]) -> str:
        '''User authorization'''
        message = f'Пользователь с логином {args[0]} не зарегестрирован!'
        if args[0] in self.users:
            message = f'Добро пожаловать, {args[0]}!'
            if self.users[args[0]]:
                message += ' Вы являетесь администратором!'
            self.current_user = args[0]
        return message

    def unlogin(self, args: list[str]) -> str:
        '''User de-auth'''
        message = 'В данную функцию не нужно передавать аргументы!'
        if len(args) == 0:
            message = 'Вы не авторизованы!'
            if self.current_user is not None:
                message = f'До свидания, {self.current_user}!'
                self.current_user = None
        return message

    def catalog(self, args: list[str]) -> str:
        '''Show catalog'''
        message = 'В данную функцию не нужно передавать аргументы!'
        if len(args) == 0:
            message = 'Каталог пуст!'
            if len(self.books_catalog) != 0:
                message = 'Каталог:'
                for book in self.books_catalog:
                    message += f'\n\t{book.title} ({book.author})'
                    message += f' --- {book.price}'
        return message

    def add_book(self, args: list[str]) -> str:
        '''Adding book into a catalog'''
        new_book = Book(
            args[0], args[1], int(args[2]), float(args[3]), args[4], args[5])
        self.books_catalog.append(new_book)
        return f'Книга "{new_book.title}" добавлена в каталог!'

    def show_cart(self, args: list[str]) -> str:
        '''Showing cart contents'''
        message = 'В данную функцию не нужно передавать аргументы!'
        if len(args) == 0:
            message = 'Ваша корзина пока пуста.'
            user_carts = list(
                filter(
                    lambda cart: cart.buyer_login == self.current_user and
                    not cart.delivery, self.carts))
            if len(user_carts) != 0 and len(user_carts[0].shop_list) != 0:
                message = 'Ваша корзина:'
                for book in user_carts[0].shop_list:
                    message += f'\n\t{book.title} ({book.author})'
                    message += f' --- {book.price}'
        return message

    def add_book_to_cart(self, args: list[str]) -> str:
        '''Adding book to cart'''
        user_carts = list(
            filter(
                lambda cart: cart.buyer_login == self.current_user and
                not cart.delivery, self.carts))
        if len(user_carts) == 0 and self.current_user is not None:
            new_cart = Cart(self.current_user, self.carts_counter)
            self.carts_counter += 1
            self.carts.append(new_cart)
            cart = new_cart
        else:
            cart = user_carts[0]

        suggested_books = list(
            filter(
                lambda book: book.title.lower() == args[0].lower(),
                self.books_catalog))
        if len(suggested_books) != 0:
            cart.add_book_to_cart(suggested_books[0])
            message = f'Книга "{suggested_books[0].title}" '
            message += 'добавлена в вашу корзину.'

        return message

    def clear_cart(self, args: list[str]) -> str:
        '''Clearing cart contents'''
        message = 'В данную функцию не нужно передавать аргументы!'
        if len(args) == 0:
            message = 'Ваша корзина очищена.'
            user_carts = list(
                filter(
                    lambda cart: cart.buyer_login == self.current_user and
                    not cart.delivery, self.carts))
            if len(user_carts) != 0:
                user_carts[0].shop_list = []

        return message

    def deliver(self, args: list[str]) -> str:
        '''Deliver cart'''
        user_carts = list(
            filter(
                lambda cart: cart.buyer_login == self.current_user and
                not cart.delivery, self.carts))
        if len(user_carts) == 0:
            return 'Ваша корзина пуста, невозможно оформить доставку!'
        cart = user_carts[0]

        cart.deliver(args[0], args[1], args[2])

        return f'Доставка оформлена, заказ #{cart.primary_key}'

    def orders(self, args: list[str]) -> str:
        '''Show list of orders'''
        message = 'В данную функцию не нужно передавать аргументы!'
        if len(args) == 0:
            message = 'У вас нет активных заказов.'
            orders = list(
                filter(
                    lambda cart: cart.buyer_login == self.current_user and
                    cart.delivery, self.carts))
            if len(orders) != 0:
                message = 'Ваши заказы:'
                for order in orders:
                    message += f'\n\tЗаказ #{order.primary_key}: '
                    message += f'{order.delivery_time}, {order.payment_method}'
        return message
