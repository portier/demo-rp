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
    <form action="/login" method="POST">
      <input type=email name=email placeholder="you@example.com" />
      <input type=submit value="Log In" />
    </form>
    <p><small><em>Code at <a href="https://github.com/portier/demo-rp">Portier/Demo-RP</a>.</em></small></p>
  </body>
</html>
