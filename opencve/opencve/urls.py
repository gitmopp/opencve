from django.contrib import admin
from django.urls import include, path

from users.views import register, CustomLoginView


urlpatterns = [
    path("__debug__/", include("debug_toolbar.urls")),
    path("", include("core.urls")),
    path("register/", register, name="register"),
    path("accounts/", include("users.urls")),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("admin/", admin.site.urls),
]
