% include('_head.tpl')
    <form class="demo" action="/logout" method="POST">
      <p>You are now logged in as <strong>{{ email }}</strong>.</p>
      <input type=submit value="Log out" />
    </form>
% include('_foot.tpl')
