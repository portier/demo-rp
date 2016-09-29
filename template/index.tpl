<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Portier Example RP</title>
    <link rel="stylesheet" href="/static/style.css" />
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body>
    <p>You can log in below:</p>
    <form action="{{ portier_origin }}/auth" method="POST">
      <input type=email name=login_hint placeholder="you@example.com" />
      <input type=hidden name=scope value="openid email" />
      <input type=hidden name=response_type value="id_token" />
      <input type=hidden name=client_id value="{{ rp_origin }}" />
      <input type=hidden name=redirect_uri value="{{ rp_origin }}/login" />
      <input type=submit value="Log In" />
    </form>
    <p><small><em>Code at <a href="https://github.com/portier/demo-rp">Portier/Demo-RP</a>.</em></small></p>
  </body>
</html>
