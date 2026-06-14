<powershell>
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-Asp-Net45

# Enable ASP.NET session state
Import-Module WebAdministration

# Create default.aspx - Session Loss Demo with Login
$$aspxContent = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<!DOCTYPE html>
<script runat="server">
protected string GetInstanceId()
{
    try
    {
        using (var client = new WebClient())
        {
            client.Headers.Add("X-aws-ec2-metadata-token-ttl-seconds", "21600");
            string token = client.UploadString("http://169.254.169.254/latest/api/token", "PUT", "");
            client.Headers.Add("X-aws-ec2-metadata-token", token);
            return client.DownloadString("http://169.254.169.254/latest/meta-data/instance-id");
        }
    }
    catch { return "N/A"; }
}

protected void Page_Load(object sender, EventArgs e)
{
    // Handle login
    if (Request.Form["action"] == "login")
    {
        Session["user"] = Request.Form["username"];
        Session["loginTime"] = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
        Session["loginHost"] = Environment.MachineName;
        Session["count"] = 0;
        Response.Redirect(Request.Url.AbsolutePath, false);
        Context.ApplicationInstance.CompleteRequest(); return;
    }
    // Handle logout
    if (Request.Form["action"] == "logout")
    {
        Session.Abandon();
        Response.Redirect(Request.Url.AbsolutePath, false);
        Context.ApplicationInstance.CompleteRequest(); return;
    }
    // Increment counter if logged in
    if (Session["user"] != null)
    {
        Session["count"] = (int)Session["count"] + 1;
    }
}
</script>
<html>
<head>
  <title>ASG Session Demo - Why Sysprep Matters</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: linear-gradient(135deg, #1e3a5f 0%, #0f2027 100%); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
    .top-bar { background: #222; color: #fff; padding: 10px 20px; position: fixed; top: 0; left: 0; width: 100%; z-index: 999; font-size: 0.85em; text-align: center; }
    .top-bar span { color: #4ade80; font-weight: 600; }
    .card { background: #fff; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 40px; max-width: 600px; width: 100%; margin-top: 50px; }
    .header { text-align: center; margin-bottom: 24px; }
    .header h1 { font-size: 1.5em; color: #1e3a5f; margin-bottom: 6px; }
    .header p { color: #6b7280; font-size: 0.85em; }
    .login-form { text-align: center; padding: 30px 0; }
    .login-form input[type="text"] { padding: 12px 20px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em; width: 60%; margin-bottom: 12px; }
    .login-form button, .btn { background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: #fff; border: none; padding: 12px 28px; border-radius: 8px; font-size: 0.95em; cursor: pointer; font-weight: 600; }
    .login-form button:hover, .btn:hover { opacity: 0.9; }
    .btn-red { background: linear-gradient(135deg, #ef4444, #b91c1c); }
    .info-grid { display: grid; gap: 10px; margin: 20px 0; }
    .info-item { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 18px; display: flex; justify-content: space-between; align-items: center; }
    .info-item .label { font-size: 0.8em; color: #64748b; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-item .value { font-family: "Cascadia Code", "Fira Code", monospace; font-size: 0.85em; color: #1e293b; font-weight: 600; }
    .alert { border-radius: 10px; padding: 14px 18px; margin: 12px 0; font-size: 0.85em; }
    .alert-green { background: #dcfce7; border: 1px solid #86efac; color: #166534; }
    .alert-red { background: #fee2e2; border: 1px solid #fca5a5; color: #991b1b; }
    .alert-blue { background: #dbeafe; border: 1px solid #93c5fd; color: #1e40af; }
    .counter-item { background: linear-gradient(135deg, #3b82f6, #1d4ed8); border: none; }
    .counter-item .label { color: rgba(255,255,255,0.8); }
    .counter-item .value { color: #fff; font-size: 1.3em; }
    .section-title { font-size: 0.75em; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin: 16px 0 8px; font-weight: 600; }
    .footer { text-align: center; margin-top: 20px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
    .footer p { color: #94a3b8; font-size: 0.75em; line-height: 1.6; }
    .badge { display: inline-block; font-size: 0.7em; padding: 3px 10px; border-radius: 20px; font-weight: 600; }
    .badge-green { background: #dcfce7; color: #166534; }
    .badge-yellow { background: #fef3c7; color: #92400e; }
  </style>
</head>
<body>
  <div class="top-bar">
    Running on: <span><% Response.Write(Environment.MachineName); %></span>
    &nbsp;|&nbsp; Instance: <span><% Response.Write(GetInstanceId()); %></span>
    &nbsp;|&nbsp; Sysprep assigns unique hostname per instance from AMI
  </div>

  <div class="card">
    <div class="header">
      <h1>ASG Instance Refresh & Session Demo</h1>
      <p>Demonstrates why InProc sessions break during ASG Instance Refresh</p>
    </div>

    <% if (Session["user"] == null) { %>
      <!-- LOGIN FORM -->
      <div class="alert alert-blue">
        <strong>Demo:</strong> Login below, then trigger an ASG Instance Refresh.
        Your session (stored in server memory) will be lost when this instance is replaced.
      </div>
      <form method="post" class="login-form">
        <input type="hidden" name="action" value="login" />
        <input type="text" name="username" placeholder="Enter your name" required /><br/>
        <button type="submit">Login</button>
      </form>

    <% } else { %>
      <!-- LOGGED IN VIEW -->
      <div class="alert alert-green">
        Logged in as <strong><% Response.Write(Session["user"]); %></strong>
        <span class="badge badge-green">SESSION ACTIVE</span>
      </div>

      <div class="section-title">Current Server</div>
      <div class="info-grid">
        <div class="info-item">
          <span class="label">Hostname (after Sysprep)</span>
          <span class="value"><% Response.Write(Environment.MachineName); %></span>
        </div>
        <div class="info-item">
          <span class="label">Instance ID</span>
          <span class="value"><% Response.Write(GetInstanceId()); %></span>
        </div>
      </div>

      <div class="section-title">Session State (InProc - Server Memory)</div>
      <div class="info-grid">
        <div class="info-item">
          <span class="label">Session ID</span>
          <span class="value"><% Response.Write(Session.SessionID.Substring(0, 16) + "..."); %></span>
        </div>
        <div class="info-item">
          <span class="label">Logged in at</span>
          <span class="value"><% Response.Write(Session["loginTime"]); %></span>
        </div>
        <div class="info-item">
          <span class="label">Original Host</span>
          <span class="value"><% Response.Write(Session["loginHost"]); %></span>
        </div>
        <div class="info-item counter-item">
          <span class="label">Page Views This Session</span>
          <span class="value"><% Response.Write(Session["count"]); %></span>
        </div>
      </div>

      <% if ((string)Session["loginHost"] != Environment.MachineName) { %>
        <div class="alert alert-red">
          <strong>SESSION MISMATCH!</strong> You logged in on
          <strong><% Response.Write(Session["loginHost"]); %></strong> but are now on
          <strong><% Response.Write(Environment.MachineName); %></strong>.
          This means your original instance was terminated during Instance Refresh!
        </div>
      <% } else { %>
        <div class="alert alert-blue">
          <strong>Sticky:</strong> You are still on the same host. Trigger an Instance Refresh
          to see what happens when this instance is replaced.
        </div>
      <% } %>

      <div style="text-align:center; margin-top:16px;">
        <form method="post" style="display:inline;">
          <input type="hidden" name="action" value="logout" />
          <button type="submit" class="btn btn-red">Logout</button>
        </form>
      </div>

    <% } %>

    <div class="footer">
      <p>
        <strong>What this demo proves:</strong><br/>
        1. Sysprep gives each ASG instance a unique hostname (no SID conflicts in AD)<br/>
        2. InProc sessions are lost when the instance is terminated during refresh<br/>
        3. Sticky sessions only work while the server is alive<br/>
        4. Solution: Use Redis/DynamoDB/SQL for session state, or JWT tokens
      </p>
      <p style="margin-top:8px;">
        Session Mode: <span class="badge badge-yellow">InProc (Server Memory)</span>
      </p>
    </div>
  </div>
</body>
</html>
"@
Set-Content -Path "C:\inetpub\wwwroot\default.aspx" -Value $$aspxContent -Encoding UTF8

# Remove default IIS pages
Remove-Item -Path "C:\inetpub\wwwroot\iisstart.htm" -ErrorAction SilentlyContinue
Remove-Item -Path "C:\inetpub\wwwroot\iisstart.png" -ErrorAction SilentlyContinue
</powershell>
