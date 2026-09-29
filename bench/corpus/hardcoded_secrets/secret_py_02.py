"""Practice sample: Django-style SECRET_KEY literal."""
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgres',
        'NAME': 'appdb',
        'USER': 'app',
        'PASSWORD': 'sup3rs3cret-prod-password',
    }
}
SECRET_KEY = 'd9tJq8Xy7WvN0aB1cD2eF3gH4iJ5kL6mN0aB1c'
