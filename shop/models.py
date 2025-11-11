from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.text import slugify


class User(AbstractUser):
    nombre = models.CharField(max_length=50,blank=True)
    telefono = models.CharField(max_length=50, blank=True, null=True)
    cpp = models.IntegerField(blank=True, null=True)
    calle = models.CharField(max_length=50,blank=True)
    colonia = models.CharField(max_length=50,blank=True)
    municipio = models.CharField(max_length =20,blank=True)
    estado = models.CharField(max_length=20,blank=True) 
    ciudad = models.CharField(max_length=20,blank=True) 

def validate_stock_field(value):
    """
    Validate that the stock field is a list of exactly 5 numbers.
    Each number corresponds to a size (S, M, L, XL, U).
    Raises ValidationError if the value is not a list of 5 numbers.
    """
    if not isinstance(value, list):
        raise ValidationError("Value must be a list.")
    if len(value) != 5:
        raise ValidationError("List must contain exactly 5 elements.")
    if not all(isinstance(x, (int, float)) for x in value):
        raise ValidationError("All elements must be numbers (int or float).")
    
def default_stock():
    return [0, 0, 0, 0, 0]

class Item(models.Model): 
    CATEGORY_CHOICES = [
        ('Classic', 'Classic'),
        ('Season', 'Season'),
        ('Prime', 'Prime'),
        ('Gorras', 'Gorras'),
        ('Calcetines', 'Calcetines'),
        ('Hoddie', 'Hoddie'),
        ('Crew neck', 'Crew neck'),
        ('Stickers', 'Stickers'),
        ('Prints', 'Prints'),
    ]
    nombre= models.CharField(max_length=64)
    variante = models.CharField(max_length=256, blank=True)
    stock = models.JSONField(default=default_stock, validators=[validate_stock_field])
    precio = models.IntegerField()
    categoria = models.CharField(max_length=64, choices=CATEGORY_CHOICES)
    pic0 = models.CharField(max_length=256)
    n_pics = models.IntegerField()
    pic1 = models.CharField(max_length=256, blank=True)
    pic2 = models.CharField(max_length=256, blank=True)
    pic3 = models.CharField(max_length=256, blank=True)
    pic4 = models.CharField(max_length=256, blank=True)
    slug = models.SlugField(blank=True, null=True)

    def save(self, *args, **kwargs):
        # Si no tiene slug, lo genera a partir del nombre
        if not self.slug:
            self.slug = slugify(self.nombre)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return f"/product/{self.slug}/"

    def __str__(self):
        return  f"{self.nombre}"

class Carrito(models.Model): 
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="item_watched")    
    cantidad = models.IntegerField()
    talla = models.CharField(max_length=64, blank=True)
    variante = models.CharField(max_length=256, blank=True)
    user= models.ForeignKey(User,on_delete=models.CASCADE, related_name="watcher")

class Pedido(models.Model): 
    ESTATUS_CHOICES = [ #Tuple not necesary. C ould change for list
    ('Pedido y Pagado', 'Pedido y Pagado'),
    ('Enviado', 'Enviado'),
    ('Recibido', 'Recibido'),
    ]
    user= models.ForeignKey(User,on_delete=models.CASCADE, related_name="buyer", null=True, blank=True)
    estatus = models.CharField(max_length=16, choices=ESTATUS_CHOICES)
    fecha = models.DateTimeField()
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="item_bougth")    
    cantidad = models.IntegerField()
    talla = models.CharField(max_length=64, blank=True)
    variante = models.CharField(max_length=64, blank=True)
    envio = models.CharField(blank = True, max_length=50)
    guest_info = models.TextField(blank=True)

    def __str__(self):
        if self.user:
            return f"Pedido {self.user.username} - {self.fecha.strftime('%Y-%m-%d %H:%M')}"
        else:
            return f"Pedido Anónimo - {self.fecha.strftime('%Y-%m-%d %H:%M')}"