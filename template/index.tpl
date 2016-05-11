<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Let's Auth Example RP</title>
  </head>
  <body>
    % if email:
    <p>Hello! You are logged in as <strong>{{ email }}</strong>.</p>
    <p>You can <a href="/logout">Log Out</a>.</p>
    % else:
    <p>Hello! You are not logged in.</p>
    <form action="https://{{ META['LA_HOSTNAME'] }}/auth" method="POST">
      <input type=email name=login_hint placeholder="you@example.com" />
      <input type=hidden name=scope value="openid email" />
      <input type=hidden name=response_type value="id_token" />
      <input type=hidden name=client_id value="{{ META['RP_ORIGIN'] }}" />
      <input type=hidden name=redirect_uri value="{{ META['RP_ORIGIN'] + '/login' }}" />
      <input type=submit value="Log In" />
    </form>
    % end
  </body>
</html>
