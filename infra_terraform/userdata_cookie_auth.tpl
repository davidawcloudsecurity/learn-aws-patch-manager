Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-Asp-Net45

# Fetch JWT signing key from Parameter Store
$$signingKey = (Get-SSMParameter -Name "/${project_tag}/jwt-signing-key" -WithDecryption $$true).Value

# Create default.aspx with cookie-based token auth
$$aspxContent = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Text" %>
<!DOCTYPE html>
<script runat="server">
// Key fetched from Parameter Store at boot, injected here
private static string SIGNING_KEY = "$$signingKey";

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

private string Sign(string data)
{
    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SIGNING_KEY)))
    {
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }
}

private string CreateToken(string username)
{
    string expiry = DateTime.UtcNow.AddHours(24).ToString("o");
    string payload = username + "|" + expiry;
    string signature = Sign(payload);
    return Convert.ToBase64String(Encoding.UTF8.GetBytes(payload + "|" + signature));
}

private string ValidateToken(string token)
{
    try
    {
        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(token));
        string[] parts = decoded.Split('|');
        if (parts.Length != 3) return null;
        string username = parts[0];
        string expiry = parts[1];
        string signature = parts[2];
        // Check expiry
        if (DateTime.Parse(expiry) < DateTime.UtcNow) return null;
        // Verify signature
        string expectedSig = Sign(username + "|" + expiry);
        if (signature != expectedSig) return null;
        return username;
    }
    catch { return null; }
}

private string currentUser = null;
private int pageViews = 0;

protected void Page_Load(object sender, EventArgs e)
{
    // Handle login
    if (Request.Form["action"] == "login" && !string.IsNullOrEmpty(Request.Form["username"]))
    {
        string token = CreateToken(Request.Form["username"]);
        var cookie = new HttpCookie("auth_token", token);
        cookie.HttpOnly = true;
        cookie.Expires = DateTime.UtcNow.AddHours(24);
        Response.Cookies.Add(cookie);
        // Set page view counter cookie
        var pvCookie = new HttpCookie("page_views", "1");
        pvCookie.Expires = DateTime.UtcNow.AddHours(24);
        Response.Cookies.Add(pvCookie);
        Response.Redirect(Request.Url.AbsolutePath, false);
        Context.ApplicationInstance.CompleteRequest(); return;
    }
    // Handle logout
    if (Request.Form["action"] == "logout")
    {
        var cookie = new HttpCookie("auth_token", "");
        cookie.Expires = DateTime.UtcNow.AddDays(-1);
        Response.Cookies.Add(cookie);
        var pvCookie = new HttpCookie("page_views", "");
        pvCookie.Expires = DateTime.UtcNow.AddDays(-1);
        Response.Cookies.Add(pvCookie);
        Response.Redirect(Request.Url.AbsolutePath, false);
        Context.ApplicationInstance.CompleteRequest(); return;
    }
    // Validate token from cookie
    if (Request.Cookies["auth_token"] != null)
    {
        currentUser = ValidateToken(Request.Cookies["auth_token"].Value);
        if (currentUser != null && Request.Cookies["page_views"] != null)
        {
            pageViews = int.Parse(Request.Cookies["page_views"].Value) + 1;
            var pvCookie = new HttpCookie("page_views", pageViews.ToString());
            pvCookie.Expires = DateTime.UtcNow.AddHours(24);
            Response.Cookies.Add(pvCookie);
        }
    }
}
</script>
<html>
<head>
  <title>Cookie Token Auth Demo (Survives Instance Refresh)</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: linear-gradient(135deg, #065f46 0%, #064e3b 100%); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
    .top-bar { background: #222; color: #fff; padding: 10px 20px; position: fixed; top: 0; left: 0; width: 100%; z-index: 999; font-size: 0.85em; text-align: center; }
    .top-bar span { color: #34d399; font-weight: 600; }
    .card { background: #fff; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 40px; max-width: 600px; width: 100%; margin-top: 50px; }
    .header { text-align: center; margin-bottom: 24px; }
    .header h1 { font-size: 1.5em; color: #065f46; margin-bottom: 6px; }
    .header p { color: #6b7280; font-size: 0.85em; }
    .login-form { text-align: center; padding: 30px 0; }
    .login-form input[type="text"] { padding: 12px 20px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em; width: 60%; margin-bottom: 12px; }
    .login-form button, .btn { background: linear-gradient(135deg, #10b981, #059669); color: #fff; border: none; padding: 12px 28px; border-radius: 8px; font-size: 0.95em; cursor: pointer; font-weight: 600; }
    .btn-red { background: linear-gradient(135deg, #ef4444, #b91c1c); }
    .info-grid { display: grid; gap: 10px; margin: 20px 0; }
    .info-item { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 18px; display: flex; justify-content: space-between; align-items: center; }
    .info-item .label { font-size: 0.8em; color: #64748b; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-item .value { font-family: "Cascadia Code", "Fira Code", monospace; font-size: 0.85em; color: #1e293b; font-weight: 600; }
    .alert { border-radius: 10px; padding: 14px 18px; margin: 12px 0; font-size: 0.85em; }
    .alert-green { background: #dcfce7; border: 1px solid #86efac; color: #166534; }
    .alert-blue { background: #dbeafe; border: 1px solid #93c5fd; color: #1e40af; }
    .counter-item { background: linear-gradient(135deg, #10b981, #059669); border: none; }
    .counter-item .label { color: rgba(255,255,255,0.8); }
    .counter-item .value { color: #fff; font-size: 1.3em; }
    .section-title { font-size: 0.75em; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin: 16px 0 8px; font-weight: 600; }
    .footer { text-align: center; margin-top: 20px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
    .footer p { color: #94a3b8; font-size: 0.75em; line-height: 1.6; }
    .badge { display: inline-block; font-size: 0.7em; padding: 3px 10px; border-radius: 20px; font-weight: 600; }
    .badge-green { background: #dcfce7; color: #166534; }
  </style>
</head>
<body>
  <div class="top-bar">
    Mode: <span>Cookie Token (HMAC-SHA256)</span>
    &nbsp;|&nbsp; Running on: <span><% Response.Write(Environment.MachineName); %></span>
    &nbsp;|&nbsp; Key from: <span>SSM Parameter Store</span>
  </div>

  <div class="card">
    <div class="header">
      <h1>Cookie Token Auth Demo</h1>
      <p>Session survives instance refresh â€” no server-side state</p>
    </div>

    <% if (currentUser == null) { %>
      <div class="alert alert-blue">
        <strong>Mode B:</strong> Auth token stored in a signed cookie.
        Trigger Instance Refresh â€” you'll stay logged in on the new instance.
      </div>
      <form method="post" class="login-form">
        <input type="hidden" name="action" value="login" />
        <input type="text" name="username" placeholder="Enter your name" required /><br/>
        <button type="submit">Login</button>
      </form>

    <% } else { %>
      <div class="alert alert-green">
        Logged in as <strong><% Response.Write(currentUser); %></strong>
        <span class="badge badge-green">TOKEN VALID</span>
      </div>

      <div class="section-title">Current Server</div>
      <div class="info-grid">
        <div class="info-item">
          <span class="label">Hostname (Sysprep)</span>
          <span class="value"><% Response.Write(Environment.MachineName); %></span>
        </div>
        <div class="info-item">
          <span class="label">Instance ID</span>
          <span class="value"><% Response.Write(GetInstanceId()); %></span>
        </div>
      </div>

      <div class="section-title">Token Info (Client-Side Cookie)</div>
      <div class="info-grid">
        <div class="info-item">
          <span class="label">Auth Method</span>
          <span class="value">HMAC-SHA256 Signed Cookie</span>
        </div>
        <div class="info-item">
          <span class="label">Key Source</span>
          <span class="value">SSM Parameter Store</span>
        </div>
        <div class="info-item counter-item">
          <span class="label">Page Views (Cookie Counter)</span>
          <span class="value"><% Response.Write(pageViews); %></span>
        </div>
      </div>

      <div class="alert alert-blue">
        <strong>Try it:</strong> Trigger an Instance Refresh. When the new instance takes over,
        you'll still be logged in because the token is in your browser cookie and any instance
        can verify it with the same signing key from Parameter Store.
      </div>

      <div style="text-align:center; margin-top:16px;">
        <form method="post" style="display:inline;">
          <input type="hidden" name="action" value="logout" />
          <button type="submit" class="btn btn-red">Logout</button>
        </form>
      </div>

    <% } %>

    <div class="footer">
      <p>
        <strong>Why this works after Instance Refresh:</strong><br/>
        1. Token lives in browser cookie â€” not in server memory<br/>
        2. All instances share the same signing key from Parameter Store<br/>
        3. Any instance can verify the HMAC signature<br/>
        4. No database, no Redis, no server-side session
      </p>
      <p style="margin-top:8px;">
        Session Mode: <span class="badge badge-green">Cookie Token (Stateless)</span>
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
