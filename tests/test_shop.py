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
