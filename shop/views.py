from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
import datetime
from django.db import IntegrityError
from random import randint
from .models import User, Item, Carrito, Pedido
import stripe
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from collections import OrderedDict
from django.utils import timezone
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.hashers import make_password
from types import SimpleNamespace
import json
import requests
import time

from .utils import (
    get_cart_for_request,
    remove_item_from_cart,
    calcular_subtotal,
    prevent_overselling,
    place_order,
    send_order_confirmation_email,
    send_authentication_request_email,
    send_password_reset_email,
    hash_str,
)

stripe.api_key = settings.STRIPE_SECRET_KEY

ENVIO_PRICES = {
    "Correos de México": 60,
    "Estafeta/DHL": 130,
    "Local": 0,
}


# def index(request):
#     #Inicializar variables
#     request.session["message"] = False
#     request.session["fromenvio"] = False
#     #Render main page
#     return render(request,"shop/home.html",{})

def apparel(request):

    #Inicializar variable 
    request.session["message"] = False
    if request.method == "GET": 

        # TODO: Rename item categories in the admin panel 
        classics = Item.objects.filter(categoria="Classic")
        season = Item.objects.filter(categoria="Season")
        prime = Item.objects.filter(categoria="Prime")

        #Render apparel page
        return render(request,"shop/apparel.html", {
            "classics" : classics,
            "season" : season,
            "prime" : prime
        })

    else:
        # User wants to see an item  
        item_id = request.POST["item_id"]
        # Save to session item_id and redirect to view page
        request.session['item_id'] = item_id
        return redirect('product_detail', slug=Item.objects.get(id=item_id).slug)
    
def apparel_accesorios(request):
    # NOTE: Configurado por el momento solo para playeras 

    # Inicializar variable
    request.session["message"] = False
    if request.method == "GET": 

        # Playeras 
        prints = Item.objects.filter(categoria="Prints")

        #Render apparel page
        return render(request,"shop/apparel_accesorios.html", {
            "prints": prints,
        })

    else:
        # User wants to see an item  
        item_id = request.POST["item_id"]
        # Save to session item_id and redirect to view page
        request.session['item_id'] = item_id
        return redirect('product_detail', slug=Item.objects.get(id=item_id).slug)

def product_detail(request, slug): 

    if request.method == "GET": #Show item details
        # Query item
        aitem = get_object_or_404(Item, slug=slug)
        # Image adress vector post procesing
        n_pics = aitem.n_pics
        pic_adress = []
        for i in range(0,n_pics):
            pic_name = "pic" + str(i + 1)
            pic_adress.append(getattr(aitem,pic_name))
        stock = aitem.stock
        # stock is a list of numbers, if all of them are 0, then the item is out of stock
        out_of_stock = all(x == 0 for x in stock)

        tallas = ['CH', 'M', 'G', 'XG', 'U'] #{tallas_disponibles(stock)}

        return render(request, "shop/item.html", {
            "pic_adress" : pic_adress,
            "item" : aitem,
            "out_of_stock": out_of_stock, 
            "tallas" : tallas,	
        })

    else: # Añadir al carrito
        #Get information of item from form
        talla = request.POST["talla"]
        cantidad = request.POST["cantidad"]
        variante= request.POST.get('variante', False) #Provides a value if it does not exist
        aitem = get_object_or_404(Item, slug=slug)
        item_id = aitem.id
        #Validar talla y cantidad
        if talla == "TALLA" or cantidad == "CANTIDAD":
            messages.warning(request, 'Selecciona talla y cantidad.')
            return redirect('product_detail', slug=slug)
        if variante == "VARIANTE":
            messages.warning(request, 'Selecciona variante')
            return redirect('product_detail', slug=slug)

        else:
            # Non logged users: allow adding to cart without login
            if request.user.id is None:
                # Save carrito information into session. Not database.
                request.session['carrito'] = request.session.get('carrito', [])
                request.session['carrito'].append({
                    'item_id': item_id,
                    'cantidad': cantidad,
                    'talla': talla,
                    'variante': variante
                })
            # Logged user: its ok to save carrito directly into database 
            else: 
                #Agregar al carrito
                carro = Carrito(
                    item = Item.objects.get(id = item_id),
                    cantidad = cantidad,
                    talla = talla,
                    user = User.objects.get(id=request.user.id), 
                    variante = variante
                    )
                carro.save()
            #Redireccionar al carrito
            return redirect('carrito')
    
def login_view(request):
    if request.method == "POST":
        login_input = request.POST["username"]  # could be username or email
        password = request.POST["password"]

        user = authenticate(request, username=login_input, password=password)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse("index"))
        else:
            messages.error(request, "Usuario o contraseña inválidos")
    return render(request, "shop/login.html")

def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            messages.warning(request, " Las contraseñas no coinciden ")
            return render(request, "shop/register.html", )

        # Ensure email is not already registered
        if User.objects.filter(email=email).exists():
            messages.error(request, "Ya existe un usuario con ese correo electrónico.")
            return render(request, "shop/register.html")
        
        # Ensure username is not already taken
        if User.objects.filter(username=username).exists():
            messages.error(request, "Ya existe un usuario con ese nombre de usuario.")
            return render(request, "shop/register.html")
        
        # Attempt to create new user
        try:
            user = User.objects.create_user(username, email, password)
            user.save()
        except IntegrityError:
            messages.error(request,"Nombre de usuario no disponible")
            return render(request, "shop/register.html")
        
        # Prepare email confirmation
        current_site = get_current_site(request)
        mail_subject = 'Activate your account'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = f"http://{current_site.domain}/activate/{uid}/{token}/"

        # Send authentication email
        send_authentication_request_email(email, username, activation_link)
        return render(request, "shop/confirm_email.html", {
            "email": email
        })

    else:
        return render(request, "shop/register.html")

def activate(request, uidb64, token):
    """
    Activates a user account, after user clicks the activation link sent via email.
    """
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        # Set backend explicitly
        user.backend = 'shop.backends.UsernameOrEmailBackend'
        login(request, user)  # Automatically log in
        # Para que se marque "Agrega tu información de usuario para poder comprar"
        request.session["message"] = True
        return redirect('user')  # or your desired view name
    else:
        print("Activation link is invalid")
        messages.error(request, "El enlace de activación es inválido o ha expirado.")
        return HttpResponse('Activation link is invalid!')

def password_reset_view(request):
    """
    Displays the password reset form.
    """
    return render(request, "shop/password_reset_request.html", {
    })

def coming_soon(request):
    """
    Displays the password reset form.
    """
    return render(request, "shop/coming_soon.html", {
    })

def password_reset_request(request):
    """
    Handles initial password reset request by email.
    """
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
            current_site = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f"http://{current_site.domain}/reset-password/{uid}/{token}/"

            send_password_reset_email(email, reset_link)
        except User.DoesNotExist:
            pass  # Do nothing to avoid revealing if email exists

        messages.success(request, "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña.")
        return redirect("login_view")

    return render(request, "shop/password_reset_request.html")
    
def custom_password_reset_confirm(request, uidb64, token):
    """
    Handles setting the new password after clicking the email link.
    """
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == "POST":
            new_password = request.POST.get("new_password1")
            confirm_password = request.POST.get("new_password2")

            if not new_password or not confirm_password:
                messages.error(request, "Por favor completa ambos campos.")
            elif new_password != confirm_password:
                messages.error(request, "Las contraseñas no coinciden.")
            else:
                user.password = make_password(new_password)
                user.save()
                messages.success(request, "Contraseña cambiada con éxito. Ahora puedes iniciar sesión.")
                return redirect("login_view")

        return render(request, "shop/password_reset_form.html", {"uidb64": uidb64, "token": token})
    else:
        messages.error(request, "El enlace no es válido o ha expirado. Intenta de nuevo.")
        return redirect("password_reset_request")

def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse("index"))        

def carrito(request):

    if request.method == "GET":
        subtotal, carrito_items = calcular_subtotal(request)
        empty = len(carrito_items) == 0
        return render(request, "shop/cart.html", {
            "carrito": carrito_items,
            "subtotal": subtotal,
            "empty": empty
        })

    else:

        method = request.POST["method"]

        if method == "quitar": # Quitar item del carrito
            remove_item_from_cart(request)
            return redirect('carrito')

        elif method == "select_envio": # Proseguir al método de envío
            # NOTE: Button should not render if the car is empty (could this latter be lend to a vulnerability issue?)
            
            if request.user.is_authenticated:
                # Logged-in → DB cart
                user_cart = Carrito.objects.filter(user=request.user)
            else:
                # Guest → Session cart → fake objects
                session_cart = request.session.get("carrito", [])
                user_cart = []
                for entry in session_cart:
                    try:
                        item = Item.objects.get(id=entry["item_id"])
                    except Item.DoesNotExist:
                        continue  # skip invalid item
                    #TODO : this needs documentation
                    fake_entry = SimpleNamespace(
                        item=item,
                        talla=entry["talla"],
                        cantidad=int(entry["cantidad"]),
                    )
                    user_cart.append(fake_entry)

            # Prevent overselling
            overselling = prevent_overselling(request, user_cart)
            if overselling:
                return redirect('carrito')
            else:
                return render(request, "shop/envio.html")

        elif method == "goto_adress":
            """
            User has selected a shipping method and wants to proceed to address input.
            Works for logged-in users and guests.
            """
            envio = request.POST["envio"]
            request.session["envio"] = envio

            if request.user.is_authenticated:
                # ✅ Logged in → check if address is already saved in user profile
                info = User.objects.get(id=request.user.id)
                calle = getattr(info, "calle", "") or ""
                domicilio = len(calle) > 0

                if not domicilio:
                    # Ask the user to fill address form
                    return render(request, "shop/adress.html", {
                        "is_guest": False,   # so template knows who we are
                        "envio": envio,
                    })
                else:
                    # Address exists → continue
                    return render(request, "shop/almost.html", {
                        "info": info,
                        "is_guest": False,
                        "envio": envio,
                    })

            else:
                # 🚨 Guest checkout
                # Check if we already have address saved in session
                guest_info = request.session.get("guest_info", {})
                domicilio = bool(guest_info.get("calle"))

                if not domicilio:
                    # Ask guest for address (store in session after form submit)
                    return render(request, "shop/adress.html", {
                        "is_guest": True,
                        "envio": envio,
                    })
                else:
                    # Guest already filled it before
                    return render(request, "shop/almost.html", {
                        "info": guest_info,  # pass dict instead of User object
                        "is_guest": True,
                        "envio": envio,
                    })

        elif method == "save_adress":
            if request.user.is_authenticated:
                # ✅ Logged-in user → save to DB
                userinfo = User.objects.get(id=request.user.id)
                userinfo.nombre = request.POST.get("nombre", "")
                userinfo.telefono = request.POST.get("telefono", "")
                userinfo.calle = f"{request.POST.get('calle', '')}. Referencia: {request.POST.get('referencia', '')}".strip()
                userinfo.colonia = request.POST.get("colonia", "")
                userinfo.estado = request.POST.get("estado", "")
                userinfo.ciudad = request.POST.get("ciudad", "")
                userinfo.cpp = request.POST.get("cpp", "")
                userinfo.save()

                info_to_render = userinfo

            else:
                # 🚨 Guest user → save in session
                guest_info = {
                    "email": request.POST.get("email", ""),
                    "nombre": request.POST.get("nombre", ""),
                    "telefono": request.POST.get("telefono", ""),
                    "calle": f"{request.POST.get('calle', '')}. Referencia: {request.POST.get('referencia', '')}".strip(),
                    "colonia": request.POST.get("colonia", ""),
                    "estado": request.POST.get("estado", ""),
                    "ciudad": request.POST.get("ciudad", ""),
                    "cpp": request.POST.get("cpp", ""),
                }
                request.session["guest_info"] = guest_info
                request.session.modified = True

                info_to_render = guest_info  # pass dict to template

            # Redirect/render "almost" page
            return render(request, "shop/almost.html", {
                "info": info_to_render,
                "is_guest": not request.user.is_authenticated,
            })

        elif method == "modify_adress":
            return render(request, "shop/adress.html", {
                "is_guest": not request.user.is_authenticated
            })

@login_required
def pedidos(request):

    if request.method == "GET":
        pedidos = Pedido.objects.filter(user=request.user).order_by('fecha')
        empty = not pedidos.exists()
        if empty:
            return render(request, "shop/pedidos.html", {"empty": True})
    
        # Agrupar por fecha exacta
        grouped = OrderedDict()
        for pedido in pedidos:
            fecha_key = pedido.fecha.replace(microsecond=0)  # Puede ser pedido.fecha.replace(microsecond=0) si quieres menos precisión
            if fecha_key not in grouped:
                grouped[fecha_key] = []
            grouped[fecha_key].append(pedido)
    
        ped_ord = list(grouped.keys())
        ped_sets = list(grouped.values())
        total = [sum(p.cantidad * p.item.precio for p in group) for group in ped_sets]
        envios = [group[0].envio for group in ped_sets]

        #Debugging: 
        print("DEBUG ped_ord:", ped_ord)
        print("DEBUG ped_sets:", ped_sets)  
        print("DEBUG total:", total)
        print("DEBUG envios:", envios)
        ######################################
    
        # ...el resto de tu lógica para envio_descrip, envio_price, ttotal...
                ################################ Actually bad design
        # TODO: Review this
        envio_descrip = []
        envio_price = []
        # Optimized shipping description and price assignment
        envio_map = {
            "express": ("Nacional - Correos de México", ENVIO_PRICES.get("Correos de México", 60)),
            "estafeta": ("Nacional - Estafeta/DHL", ENVIO_PRICES.get("Estafeta/DHL", 130)),
            "local": ("Local", ENVIO_PRICES.get("Local", 0)),
        }
        for envio in envios:
            descrip, price = envio_map.get(envio, ("Otro", 0))
            envio_descrip.append(descrip)
            envio_price.append(price)
        ######################################      
        ttotal = []
        for sub,enviop in zip(total,envio_price):
            ttotal.append(sub+enviop)

        #Para mostrar método de pago
        fromenvio = request.session["fromenvio"]
        request.session["fromenvio"] = False
    
        return render(request, "shop/pedidos.html", {
            "ped_master": zip(ped_ord, total, ped_sets, envio_descrip, envio_price, ttotal),
            "empty": False,
            "fromenvio": request.session.get("fromenvio", False)
        })

@login_required
def user(request):

    if request.method == "GET":
        #Get user info
        info = User.objects.get(id=request.user.id)
        if request.session["message"]: 
            messages.info(request, "Añade tu información de dirección y contacto para poder comprar")
            request.session["message"] = False 
        return render(request,"shop/user.html", {
            "info": info
        })

    else:
        #User is trying to update information
        # I suppose information is correctly formated. Probably, sanitize inputs in the future

        #Update user information
        userinfo = User.objects.get(id = request.user.id)
        userinfo.nombre = request.POST["nombre"]
        userinfo.telefono = request.POST["telefono"]
        userinfo.calle = request.POST["calle"]
        userinfo.colonia = request. POST["colonia"]
        userinfo.estado = request.POST["estado"]
        userinfo.ciudad = request.POST["ciudad"]
        userinfo.cpp = request.POST["cpp"]
        userinfo.save()

        #Info Updated
        messages.success(request, "Información de usuario actualizada correctamente")

        #Get info
        return redirect('user')

            # return render(request, "shop/apology.html", {
            # "mesage" :
            #  })

@login_required
def user_info(request):
    if request.method == "GET":
        return render(request,"shop/adress.html", {

        })
    else: 
        return None 

@staff_member_required
def master(request):

    if request.method == "GET":
        # Mostrar pedidos master
        pedidos = Pedido.objects.all().order_by('fecha')
        empty = not pedidos.exists()
        if empty:
            return render(request, "shop/master.html", {"empty": True})

        # Agrupar por fecha exacta
        grouped = OrderedDict()
        for pedido in pedidos:
            fecha_key = pedido.fecha.replace(microsecond=0)
            if fecha_key not in grouped:
                grouped[fecha_key] = []
            grouped[fecha_key].append(pedido)

        ped_ord = list(grouped.keys())
        ped_sets = list(grouped.values())
        total = [sum(p.cantidad * p.item.precio for p in group) for group in ped_sets]
        hack = [group[0] for group in ped_sets]  # Primer pedido de cada grupo\
        print(hack)

        return render(request, "shop/master.html", {
            "ped_master": zip(hack, ped_ord, total, ped_sets),
            "empty": empty
        })

    else:
        estatus = request.POST["estatus"] # Status to be assigned
        fecha = request.POST["fecha"]      # Fecha del pedido
        user_id = request.POST["user"] #User whose pedido belongs
        #Actualizar estatus en base de datos
        pedidos = Pedido.objects.filter(fecha=fecha, user=User.objects.get(id=user_id))
        for pedido in pedidos: 
            pedido.estatus = estatus
            pedido.save()
        return redirect('master')

    ########### COSAS POR HACER DESPUES 
    # Averiguar si es posible crear funciones en django para no repetir algunos pedazos de código

@csrf_exempt
def create_checkout_session(request):
    if request.method != "POST":
        return JsonResponse({'clientSecret': '', 'error': 'Only POST method is allowed'}, status=405)

    envio = request.session.get("envio")
    cart_items = get_cart_for_request(request)
    subtotal, _ = calcular_subtotal(request)
    envio_price = ENVIO_PRICES.get(envio, 0)
    total = subtotal + envio_price

    print("DEBUG envio:", envio)
    print("DEBUG cart_items:", cart_items)
    print("DEBUG subtotal:", subtotal)

    if not envio or not cart_items or subtotal <= 0:
        print("DEBUG: Missing cart or shipping info")
        return JsonResponse({'clientSecret': '', 'error': 'Missing cart or shipping info'}, status=400)

    customer_email = (
        request.user.email
        if request.user.is_authenticated
        else request.session.get("guest_info", {}).get("email", "")
    )
    print("DEBUG customer_email:", customer_email)

    try:
        session = stripe.checkout.Session.create(
            ui_mode='embedded',
            line_items=[
                {
                    'price_data': {
                        'currency': 'mxn',
                        'product_data': {'name': 'Productos'},
                        'unit_amount': int(subtotal * 100),
                    },
                    'quantity': 1,
                },
                {
                    'price_data': {
                        'currency': 'mxn',
                        'product_data': {'name': 'Envío'},
                        'unit_amount': int(envio_price * 100),
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            customer_email=customer_email,
            allow_promotion_codes=True,
            return_url=f"{settings.DOMAIN}/checkout_return?session_id={{CHECKOUT_SESSION_ID}}",
        )
        # print("DEBUG Stripe session created:", session)
        return JsonResponse({'clientSecret': session.client_secret})
    except Exception as e:
        # print("DEBUG Stripe error:", str(e))
        return JsonResponse({'clientSecret': '', 'error': str(e)}, status=500)

def show_checkout_page(request):
    # print("DEBUG checking stripe public key:", settings.STRIPE_PUBLIC_KEY)
    return render(request, 'shop/checkout.html', {
        'stripe_public_key': settings.STRIPE_PUBLIC_KEY
    })

@csrf_exempt
def session_status(request):

    session_id = request.GET.get('session_id')
    customer_email = (
        request.user.email 
        if request.user.is_authenticated 
        else request.session.get("guest_info", {}).get("email", "")
    )

    if not session_id:
        return render(request, 'shop/payment_return.html', {
            'error': 'Missing session_id',
            }, status=400)

    try:
        session = stripe.checkout.Session.retrieve(session_id)

        if session.status == 'complete':
            # Get cart in a normalized format (list of dicts)
            cart_items = get_cart_for_request(request)
            print("Cart items:", cart_items)
            print("type:", type(cart_items))

            # Process the order
            try:
                place_order(request, cart_items)
            except Exception as e:
                print("Error in place_order:", e)
                import traceback; traceback.print_exc()

            # Prepare confirmation data
            total_pagado = session.amount_total / 100  # Convert cents to MXN
            envio = request.session.get("envio", "")
            envio_price = ENVIO_PRICES.get(envio, 0)
            content_ids = [str(item['item_id']) for item in cart_items]
            total_productos = total_pagado - envio_price

            # Send confirmation email to the customer
            try:
                send_order_confirmation_email(customer_email, cart_items, total_pagado, envio, envio_price)
            except Exception as e:
                print("Error sending confirmation email:", e)

            # Clean up cart
            if request.user.is_authenticated:
                Carrito.objects.filter(user=request.user).delete()
            else:
                request.session["carrito"] = []
                request.session.modified = True

        return render(request, 'shop/payment_return.html', {
            'status': session.status,
            'customer_email': customer_email,
            'total_productos': total_productos,
            'content_ids': content_ids,
        })
    except Exception as e:
        return render(request, 'shop/payment_return.html', {
            'error': str(e)}, status=500)

ACCESS_TOKEN = "EAAROYnRtd64BPoOzvVsebuLf9a5ozbg1soPemqj13TNYaR1GAqHJY1HC7vMQZA8zYemLDN2wUi8pAv6x9EWgIZAOf6jxq7b6MEZAyLzmgBCzw349yh6ly6AlLddydFOrTZAj23BoaQAfJlBMu7JXVxgio7kPflqbzqRAFwtziqqBGTeLdkpMj3jPu9sdIIJZBBAZDZD"
PIXEL_ID = "785382887747853"
@csrf_exempt
def meta_event(request):
    """
    Generic endpoint for sending any event to Meta's Conversions API.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body)
        event_name = data.get("event_name")
        event_id = data.get("event_id")
        event_source_url = data.get("event_source_url", "https://maneappgogo.shop")
        custom_data = data.get("custom_data", {})

        # Meta requires event name
        if not event_name:
            print("ERROR!!!!!!!!: Missing event_name")
            return JsonResponse({"error": "Missing event_name"}, status=400)

        # Build user_data dict only with available fields
        user_data = {
            "client_ip_address": request.META.get("REMOTE_ADDR"),
            "client_user_agent": request.META.get("HTTP_USER_AGENT"),
        }

        email = ""
        phone = ""
        if request.user.is_authenticated:
            email = getattr(request.user, "email", "") or ""
            phone = getattr(request.user, "telefono", "") or ""
        else:
            guest_info = request.session.get("guest_info", {})
            email = guest_info.get("email", "") or ""
            phone = guest_info.get("telefono", "") or ""

        if email:
            user_data["em"] = hash_str(email)
        if phone:
            user_data["ph"] = hash_str(phone)

        payload = {
            "data": [
                {
                    "event_name": event_name,
                    "event_time": int(time.time()),
                    "action_source": "website",
                    "event_id": event_id,
                    "event_source_url": event_source_url,
                    "user_data": user_data,
                    "custom_data": custom_data,
                }
            ],
            # "test_event_code": "TEST30363",  # <-- Move here
        }

        response = requests.post(
            f"https://graph.facebook.com/v19.0/{PIXEL_ID}/events",
            params={"access_token": ACCESS_TOKEN},
            json=payload
        )

        print(response.json())

        return JsonResponse(response.json())

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)