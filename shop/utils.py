from urllib import request
from .models import Carrito, Item, User, Pedido
from collections import defaultdict
from django.contrib import messages
from django.shortcuts import render, redirect
import datetime
from random import randint
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
import hashlib



def remove_item_from_cart(request):
    """
    Elimina un item del carrito de un usuario (logeado o no).
    """
    user = request.user
    cart_id = request.POST['cart_id']
    item_id = request.POST.get("item_id")
    cantidad = request.POST.get("cantidad")
    talla = request.POST.get("talla")
    variante = request.POST.get("variante")
    print(
        'fields received: item_id={}, cantidad={}, talla={}, variante={}'.format(
            item_id, cantidad, talla, variante
        )
    )

    if not user.is_authenticated:
        carrito = request.session.get("carrito", [])
        print("carrito antes:", carrito)

        new_cart = []
        removed = False
        for item in carrito:
            if (
                str(item["item_id"]) == str(item_id)
                and str(item.get("talla")) == str(talla)
                and str(item.get("variante")) == str(variante)
                and str(item.get("cantidad")) == str(cantidad)
                and not removed   # remove only one matching row
            ):
                removed = True
                continue
            new_cart.append(item)

        request.session["carrito"] = new_cart
        request.session.modified = True
        print("carrito despues:", request.session.get("carrito", []))
    else:
        # Remove item from database cart
        todrop = Carrito.objects.get(id=cart_id)
        todrop.delete()

    return None

def calcular_subtotal(request):
    """
    Calcula el subtotal del carrito de un usuario (logeado o no).
    Retorna (subtotal, carrito_items).
    """
    user = request.user
    subtotal = 0
    carrito_items = []

    if not user.is_authenticated:
        # Carrito from session
        carrito = request.session.get('carrito', [])
        print(f"Carrito from session: {carrito}")

        for row in carrito:
            item = Item.objects.get(id=row["item_id"])
            cantidad = int(row["cantidad"])
            subtotal += cantidad * item.precio

            carrito_items.append({
                "item": item,
                "cantidad": cantidad,
                "talla": row.get("talla"),
                "variante": row.get("variante"),
            })

    else:
        # Carrito from DB
        carrito = Carrito.objects.filter(user=user)
        subtotal = sum(row.cantidad * row.item.precio for row in carrito)
        carrito_items = carrito

    return subtotal, carrito_items

def prevent_overselling(request, user_cart):
    """ 
    Verifica que no se esté intentando comprar más de lo que hay en stock.
    Si hay un problema, muestra un mensaje de error y retorna True.
    Si no hay problemas, retorna False.
    """
    # Step 1: Aggregate quantities by (item, talla)
    cart_totals = defaultdict(int)
    for entry in user_cart:
        key = (entry.item.id, entry.talla)
        cart_totals[key] += entry.cantidad
    
    # Step 2: Check against stock
    # TODO: Verify I can get away just looking at the unique dopla
    for (item_id, talla), total_qty in cart_totals.items():
        item = Item.objects.get(id=item_id)
        talla_index = ['CH', 'M', 'G', 'XG', 'U'].index(talla)
        available = item.stock[talla_index]
        if total_qty > available:
            messages.error(
                request,
                f"No hay suficiente stock para {item.nombre} talla {talla}. Solicitaste {total_qty}, pero solo hay {available}."
            )
            overselling = True
        else:
            overselling = False
    return overselling
                
def place_order(request, temp):
    """
    Mueve los items del carrito a la tabla de pedidos y limpia el carrito.
    También, ajusta el stock de los items según la cantidad comprada.
    Se asume que el método de envío ya ha sido seleccionado y está en la sesión.
    Se asume también que esta funcion se llama sólo si hay suficiente stock.
    Funciona para ambos; usuarios logeados y no logeados.
    """

    envio = request.session.get("envio", "")
    talla_map = ['CH', 'M', 'G', 'XG', 'U']
    guest_info = request.session.get("guest_info", {})
    print("Guest info:", guest_info)
    print("Temp received in place_order:", temp, type(temp))

    for entry in temp:
        # entry is now a dict → access with ["key"]
        item_name = entry.get("nombre")
        cantidad = entry.get("cantidad", 0)
        talla = entry.get("talla")
        variante = entry.get("variante", False)

        # 🔹 Look up the Item object in DB using the name (or another unique identifier)
        try:
            item = Item.objects.get(nombre=item_name)
            print("Item found:", item)
        except Item.DoesNotExist:
            print("Item not found:", item_name)
            continue  # skip if item not found

        # 🔹 Ajustar stock de acuerdo a la talla
        if talla in talla_map:
            talla_index = talla_map.index(talla)
            stock = item.stock
            stock[talla_index] -= cantidad
            item.stock = stock
            item.save()

        # 🔹 Convert guest info dict into string
        if guest_info:
            guest_info_str = ", ".join(
                f"{key.capitalize()}: {value}"
                for key, value in guest_info.items()
                if value
            )
            print("Guest info string:", guest_info_str)
        else:
            guest_info_str = ""

        # 🔹 Crear pedido
        print("Creating Pedido with:", {
            "item": item,
            "cantidad": cantidad,
            "talla": talla,
            "variante": variante,
        })
        pedido = Pedido(
            item=item,
            cantidad=cantidad,
            talla=talla,
            variante=variante,
            user=request.user if request.user.is_authenticated else None,
            guest_info=guest_info_str,
            estatus="Pedido y Pagado",
            fecha=timezone.now(),
            envio=envio
        )
        pedido.save()

    return None

def send_order_confirmation_email(customer_email, order, total_pagado, envio, envio_price):
    """
    Sends an order confirmation email to the customer.
    """
    subject = "Confirmación de tu pedido en maneapp Shop"
    message = render_to_string('shop/email_order_confirmation.html', {
        'order': order,
        'total_pagado': total_pagado,
        'empresa_envio': envio, 
        'envio_price': envio_price
    })
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [customer_email]

    send_mail(
        subject,
        message,
        from_email,
        recipient_list,
        fail_silently=False,
        html_message=message
    )

def send_authentication_request_email(customer_email, user, activation_link):
    """
    Sends an authentication request email to the customer.
    """
    subject = "Confirma tu cuenta en maneapp Shop"
    message = render_to_string('shop/email_authentication_request.html', {
        'user': user,
        'activation_link': activation_link
    })
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [customer_email]

    send_mail(
        subject,
        message,
        from_email,
        recipient_list,
        fail_silently=False,
        html_message=message
    )

def send_password_reset_email(customer_email, reset_link):
    """
    Sends a password reset email to the customer.
    """
    subject = "Restablecer tu contraseña en maneapp Shop"
    message = render_to_string('shop/email_password_reset.html', {
        'reset_link': reset_link
    })
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [customer_email]

    send_mail(
        subject,
        message,
        from_email,
        recipient_list,
        fail_silently=False,
        html_message=message
    )

def get_cart_for_request(request):
    """
    Returns the cart items as a list of dicts, normalized for both
    authenticated users (Carrito model) and guests (session cart).
    """
    cart_items = []

    if request.user.is_authenticated:
        # Query Carrito model
        from .models import Carrito  # adjust import if needed
        carrito_qs = Carrito.objects.filter(user=request.user)

        for row in carrito_qs:
            cart_items.append({
                "item_id": row.item.id,
                "nombre": row.item.nombre,
                "precio": row.item.precio,
                "cantidad": row.cantidad,
                "talla": row.talla,
                "variante": row.variante,
            })
    else:
        # Get from session
        session_cart = request.session.get("carrito", [])
        print("Session cart:", session_cart)

        for row in session_cart:
            try:
                item = Item.objects.get(id=row["item_id"])
                cart_items.append({
                    "item_id": row["item_id"],
                    "nombre": item.nombre,
                    "precio": item.precio,
                    "cantidad": int(row["cantidad"]),  # convert to int
                    "talla": row.get("talla", ""),
                    "variante": row.get("variante", False),
                })
            except Item.DoesNotExist:
                print(f"Item with id {row['item_id']} not found in DB")
                continue

    return cart_items

# FACEBOOK DATA SHARING
import requests
import time

ACCESS_TOKEN = "EAAROYnRtd64BPoOzvVsebuLf9a5ozbg1soPemqj13TNYaR1GAqHJY1HC7vMQZA8zYemLDN2wUi8pAv6x9EWgIZAOf6jxq7b6MEZAyLzmgBCzw349yh6ly6AlLddydFOrTZAj23BoaQAfJlBMu7JXVxgio7kPflqbzqRAFwtziqqBGTeLdkpMj3jPu9sdIIJZBBAZDZD"
PIXEL_ID = "785382887747853"

def send_event(event_name, event_source_url, user_data=None, custom_data=None):
    """
    Sends a server event to Meta's Conversions API
    """
    endpoint = f"https://graph.facebook.com/v19.0/{PIXEL_ID}/events"
    event_time = int(time.time())

    payload = {
        "data": [
            {
                "event_name": event_name,
                "event_time": event_time,
                "action_source": "website",
                "event_source_url": event_source_url,
                "user_data": user_data or {},
                "custom_data": custom_data or {},
            }
        ],
        "access_token": ACCESS_TOKEN,
    }

    response = requests.post(endpoint, json=payload)
    return response.json()

def hash_str(s):
    """
    Returns a SHA256 hash of the string, formatted according to Meta's CAPI rules.
    Returns None (not an empty string) when there's nothing to hash.
    """
    if not s:
        return None  # better than returning ""
    s = str(s).strip().lower()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()