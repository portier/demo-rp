% include('_head.tpl')
    <form class="demo" action="/login" method="POST">
      <p>Try out Portier by entering your email address below:</p>
      <input type=email name=email placeholder="you@example.com" />
      <input type=submit value="Log In" />
      <p><small><em>Try a Gmail and a non-Gmail address!</em></small></p>
    </form>
% include('_foot.tpl')
