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
