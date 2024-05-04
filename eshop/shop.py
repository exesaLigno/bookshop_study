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

class Shop:

    handlers: dict[str, str] = {
        'вход': 'login',
        'выход': 'unlogin',
        'каталог': 'catalog',
        'добавить_товар': 'add_book',
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
