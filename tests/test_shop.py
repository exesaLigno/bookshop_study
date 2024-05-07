from eshop import Shop
import pytest

@pytest.fixture
def shop():
	'''
	This fixture prepares new shop with two users - user and admin
	'''
	new_shop = Shop()
	new_shop.register_user('user')
	new_shop.register_user('admin', moderator=True)
	return new_shop

@pytest.fixture
def filled_shop():
	'''
	In most part of tests it is needed to have shop with some books 
	configurated. So, to simplify usage, let's use this fixture.
	This fixture prepares new shop with two users - user and admin, and 
	with three books in catalog.
	'''
	new_shop = Shop()
	new_shop.register_user('user')
	new_shop.register_user('admin', moderator=True)
	new_shop.process('добавить_товар Идиот Достоевский 1869 399.99 Эксмо Роман')
	new_shop.process('добавить_товар "Война и мир" Толстой 1869 899.99 Эксмо Роман-эпопея')
	new_shop.process('добавить_товар 1984 Оруэлл 1948 550 Эксмо Антиутопия')
	return new_shop

def test_login_unlogin(shop):
	assert shop.process('вход user') == 'Добро пожаловать, user!'
	assert shop.process('выход') == 'До свидания, user!'

def test_double_login(shop):
	assert shop.process('вход user') == 'Добро пожаловать, user!'
	assert shop.process('вход admin') == 'Добро пожаловать, admin! Вы являетесь администратором!'

def test_double_unlogin(shop):
	assert shop.process('вход user') == 'Добро пожаловать, user!'
	assert shop.process('выход') == 'До свидания, user!'
	assert shop.process('выход') == 'Вы не авторизованы!'

def test_add_book(shop):
	assert shop.process('вход admin') == 'Добро пожаловать, admin! Вы являетесь администратором!'
	assert shop.process('каталог') == 'Каталог пуст!'
	assert shop.process('добавить_товар Идиот Достоевский 1869 399.99 Эксмо Роман') == 'Книга "Идиот" добавлена в каталог!'
	assert shop.process('добавить_товар "Война и мир" Толстой 1869 899.99 Эксмо роман-эпопея') == 'Книга "Война и мир" добавлена в каталог!'
	assert shop.process('каталог') == 'Каталог:\n\tИдиот (Достоевский) --- 399.99\n\tВойна и мир (Толстой) --- 899.99'

def test_cart(filled_shop):
	assert filled_shop.process('вход user') == 'Добро пожаловать, user!'
	assert filled_shop.process('корзина') == 'Ваша корзина пока пуста.'
	assert filled_shop.process('добавить_в_корзину "Война и мир"') == 'Книга "Война и мир" добавлена в вашу корзину.'
	assert filled_shop.process('добавить_в_корзину 1984') == 'Книга "1984" добавлена в вашу корзину.'
	assert filled_shop.process('корзина') == 'Ваша корзина:\n\tВойна и мир (Толстой) --- 899.99\n\t1984 (Оруэлл) --- 550.0'
	assert filled_shop.process('очистить_корзину') == 'Ваша корзина очищена.'
	assert filled_shop.process('корзина') == 'Ваша корзина пока пуста.'

def test_delivery(filled_shop):
	assert filled_shop.process('вход user') == 'Добро пожаловать, user!'
	assert filled_shop.process('заказы') == 'У вас нет активных заказов.'
	assert filled_shop.process('доставить "Ул. Пушкина, д. Колотушкина" "35 августа, 23:59" "Оплата при заказе"') == 'Ваша корзина пуста, невозможно оформить доставку!'
	assert filled_shop.process('добавить_в_корзину 1984') == 'Книга "1984" добавлена в вашу корзину.'
	assert filled_shop.process('доставить "Ул. Пушкина, д. Колотушкина" "32 августа, 03:47" "Оплата при получении"') == 'Доставка оформлена, заказ #0'
	assert filled_shop.process('добавить_в_корзину Идиот') == 'Книга "Идиот" добавлена в вашу корзину.'
	assert filled_shop.process('доставить "Ул. Пушкина, д. Колотушкина" "35 августа, 23:59" "Оплата при заказе"') == 'Доставка оформлена, заказ #1'
	assert filled_shop.process('заказы') == 'Ваши заказы:\n\tЗаказ #0: 32 августа, 03:47, Оплата при получении\n\tЗаказ #1: 35 августа, 23:59, Оплата при заказе'
