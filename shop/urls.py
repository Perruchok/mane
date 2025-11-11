from django.urls import path

from . import views

urlpatterns = [
    path('', views.apparel, name='index'),
    # path('apparel', views.apparel, name='apparel'),
    path('apparel_accesorios', views.apparel_accesorios, name='apparel_accesorios'),
    path('product/<slug:slug>/', views.product_detail, name = 'product_detail'),
    # path("login", views.login, name="login"),
    path("coming_soon", views.coming_soon, name="coming_soon"),
    path("logout", views.logout, name="logout"),
    path("carrito", views.carrito, name="carrito"), 
    path("pedidos", views.pedidos, name = "pedidos"), 
    path("user", views.user, name = "user"), 
    path("login_view", views.login_view, name = "login_view"), 
    path("register", views.register, name = "register"), 
    path("master", views.master, name = "master"), 
    path("logout_view", views.logout_view, name = "logout_view"), 
    path("user_info", views.user_info, name="user_info"),
    path('create-checkout-session/', views.create_checkout_session, name='create_checkout_session'),
    path('checkout', views.show_checkout_page, name='checkout'),
    path('checkout_return/', views.session_status, name='session_status'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('password_reset_view/', views.password_reset_view, name='password_reset_view'),
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path("reset-password/<uidb64>/<token>/", views.custom_password_reset_confirm, name="custom_password_reset_confirm"),
    path("api/meta/event/", views.meta_event, name="meta_event"),
]
