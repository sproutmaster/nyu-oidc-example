import json
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.shortcuts import redirect, render, redirect
from django.urls import reverse
from urllib.parse import quote_plus, urlencode

oauth = OAuth()

oauth.register(
    name='nyu',
    client_id='',
    client_secret='',
    server_metadata_url='https://qa.auth.it.nyu.edu/oauth2/oidcdiscovery/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid'},
)

def index(request):

    return render(
        request,
        "index.html",
        context={
            "session": request.session.get("user"),
            "pretty": json.dumps(request.session.get("user"), indent=4),
        },
    )

def callback(request):
    token = oauth.nyu.authorize_access_token(request)
    request.session["user"] = token
    return redirect(request.build_absolute_uri(reverse("index")))


def login(request):
    # build a full authorize callback uri
    redirect_uri = request.build_absolute_uri('/oidc/callback/')
    return oauth.nyu.authorize_redirect(request, redirect_uri)


def logout(request):
    request.session.clear()
    return redirect("https://qa.auth.it.nyu.edu/oidc/logout")
