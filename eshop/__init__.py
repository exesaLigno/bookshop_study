'''Shop module'''


class Shop:
    '''Shop class'''

    handlers: dict[str, str] = {
        'вход': 'login',
        'выход': 'unlogin',
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
