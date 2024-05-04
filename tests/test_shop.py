from eshop.shop import Shop
import pytest

@pytest.fixture
def shop():
	return Shop()

################# Auth tests #################
def test_login_unlogin(shop):
	shop.register_user('user')
	assert shop.process('вход user') == 'Добро пожаловать, user!'
	assert shop.process('выход') == 'До свидания, user!'

def test_double_login(shop):
	shop.register_user('user')
	shop.register_user('admin', moderator=True)
	assert shop.process('вход user') == 'Добро пожаловать, user!'
	assert shop.process('вход admin') == 'Добро пожаловать, admin! Вы являетесь администратором!'

def test_double_unlogin(shop):
	shop.register_user('user')
	assert shop.process('вход user') == 'Добро пожаловать, user!'
	assert shop.process('выход') == 'До свидания, user!'
	assert shop.process('выход') == 'Вы не авторизованы!'

################# General functionality #################
def test_catalog(shop):
	pass

################# Moderation tests #################

