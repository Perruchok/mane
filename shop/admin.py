from django.contrib import admin
from .models import User,Item,Carrito,Pedido

# Register your models here.
admin.site.register(User)
admin.site.register(Item)
admin.site.register(Carrito)
admin.site.register(Pedido)