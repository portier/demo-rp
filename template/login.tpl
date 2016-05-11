<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Let's Auth Example RP</title>
    <script>
      var qsFrag = window.location.hash.substr(1);
      var formData = new FormData();
      formData.set('qs', qsFrag);
      fetch('/login/xhr', { method: 'POST',
                            body: formData,
                            mode: 'same-origin',
                            credentials: 'same-origin',
                            redirect: 'error',
                          })
      .then(function(res) {
        if (!res.ok) {
          throw new Error(res.headers.get('X-Failure-Reason') || 'Unknown failure');
        }

        return res.json();
      })
      .then(function(json) { return json.redirect || window.location.origin })
      .then(function(redir) { window.location = redir })
      .catch(function(err) {
        alert("Something went wrong. Check the browser console.");
        console.error(err.message);
      });
    </script>
  </head>
  <body>
    <p>Please wait...</p>
  </body>
</html>
