// =============================================================================
// web/pages.rs — server-rendered HTML for the management GUI
//
// Minimal, dependency-free templating: each function returns a full HTML string
// built around a shared dark-themed layout. No external template engine or JS
// framework — keeps the binary self-contained (per the design brief).
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// escape
// Escape the five HTML-significant characters for safe interpolation.
// ─────────────────────────────────────────────────────────────────────────────
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Shared CSS for every page. Colors come from CSS variables so the dark/light
/// theme is a single attribute flip on <html data-theme>.
const STYLE: &str = "\
:root{\
--bg:#0e1116;--card:#161b22;--border:#30363d;--border-soft:#21262d;\
--fg:#e6edf3;--muted:#7d8590;--h2:#9da7b3;--link:#58a6ff;--brand:#3fb950;\
--accent:#238636;--accent-hover:#2ea043;--accent-fg:#fff;\
--neutral:#30363d;--neutral-fg:#e6edf3;--danger:#b62324;--danger-fg:#fff;\
--err-bg:#3d1a1d;--err-border:#f85149;--err-fg:#ffa198;\
--ok-bg:#132e1a;--ok-fg:#3fb950;--ok-border:#238636;\
--warn-bg:#3d2a12;--warn-fg:#d29922;--warn-border:#9e6a03;color-scheme:dark}\
[data-theme=light]{\
--bg:#f6f8fa;--card:#ffffff;--border:#d0d7de;--border-soft:#eaeef2;\
--fg:#1f2328;--muted:#59636e;--h2:#59636e;--link:#0969da;--brand:#1a7f37;\
--accent:#1f883d;--accent-hover:#1a7f37;--accent-fg:#fff;\
--neutral:#eaeef2;--neutral-fg:#1f2328;--danger:#cf222e;--danger-fg:#fff;\
--err-bg:#ffebe9;--err-border:#cf222e;--err-fg:#82071e;\
--ok-bg:#dafbe1;--ok-fg:#1a7f37;--ok-border:#1f883d;\
--warn-bg:#fff8c5;--warn-fg:#9a6700;--warn-border:#d4a72c;color-scheme:light}\
*{box-sizing:border-box}\
body{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}\
header{display:flex;align-items:center;justify-content:space-between;\
padding:14px 22px;background:var(--card);border-bottom:1px solid var(--border)}\
header .brand{font-weight:700;letter-spacing:.3px}\
header .brand span{color:var(--brand)}\
header .right{display:flex;align-items:center;gap:14px}\
main{max-width:880px;margin:40px auto;padding:0 22px}\
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:24px;margin-bottom:20px}\
h1{font-size:22px;margin:0 0 6px}\
h2{font-size:16px;margin:0 0 14px;color:var(--h2)}\
label{display:block;margin:14px 0 6px;font-size:13px;color:var(--h2)}\
input,textarea,select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:7px;\
background:var(--bg);color:var(--fg);font-size:14px}\
textarea{font-family:ui-monospace,monospace}\
button{margin-top:18px;padding:10px 18px;border:0;border-radius:7px;\
background:var(--accent);color:var(--accent-fg);font-weight:600;cursor:pointer;font-size:14px}\
button:hover{filter:brightness(1.08)}\
button.btn-neutral{background:var(--neutral);color:var(--neutral-fg)}\
button.btn-danger{background:var(--danger);color:var(--danger-fg)}\
button.link{background:none;color:var(--link);padding:0;margin:0;font-weight:400}\
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}\
.err{background:var(--err-bg);border:1px solid var(--err-border);color:var(--err-fg);padding:10px 12px;\
border-radius:7px;margin-bottom:8px;font-size:14px}\
.muted{color:var(--muted);font-size:13px}\
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}\
.pill.ok{background:var(--ok-bg);color:var(--ok-fg);border:1px solid var(--ok-border)}\
.pill.warn{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-border)}\
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}\
.kv{padding:12px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px}\
.kv .k{font-size:12px;color:var(--muted)}.kv .v{font-size:15px;margin-top:2px}\
table{width:100%;border-collapse:collapse;margin-top:10px}\
th{text-align:left;font-size:12px;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--border)}\
td{padding:9px 10px;border-bottom:1px solid var(--border-soft);font-size:14px;vertical-align:middle}\
tr:last-child td{border-bottom:0}\
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--fg)}\
code{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:13px}\
.themetoggle{font-size:16px;line-height:1;cursor:pointer}\
.version{position:fixed;bottom:8px;right:12px;font-size:12px;color:var(--muted);opacity:.65}\
.version a{color:var(--muted)}";

/// Inline head script: apply the saved/OS theme before paint (no flash) and a
/// toggle handler. Kept tiny and dependency-free.
const THEME_SCRIPT: &str = "\
(function(){try{var t=localStorage.getItem('ev-theme');\
if(!t){t=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';}\
document.documentElement.setAttribute('data-theme',t);}catch(e){}})();\
function evToggleTheme(){var d=document.documentElement;\
var c=d.getAttribute('data-theme')==='light'?'dark':'light';\
d.setAttribute('data-theme',c);try{localStorage.setItem('ev-theme',c);}catch(e){}}";

// ─────────────────────────────────────────────────────────────────────────────
// layout
// Wrap page `body` in the shared shell; `user` adds the header + logout control.
// ─────────────────────────────────────────────────────────────────────────────
pub fn layout(title: &str, user: Option<&str>, body: &str) -> String {
    let header_right = match user {
        Some(name) => format!(
            "<a href=\"/gui/account/password\" class=\"muted\" title=\"Account\">{}</a> &nbsp;\
             <form method=\"post\" action=\"/gui/logout\" style=\"margin:0;display:inline\">\
             <button class=\"link\" type=\"submit\">Log out</button></form>",
            escape(name)
        ),
        None => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title} · EasyVault</title><script>{script}</script><style>{style}</style></head><body>\
         <header><div class=\"brand\">Easy<span>Vault</span></div>\
         <div class=\"right\">\
         <button class=\"link themetoggle\" type=\"button\" onclick=\"evToggleTheme()\" \
         title=\"Toggle light / dark\" aria-label=\"Toggle theme\">◐</button>{right}</div></header>\
         <main>{body}</main>\
         <div class=\"version\">v{version}</div></body></html>",
        title = escape(title),
        script = THEME_SCRIPT,
        style = STYLE,
        right = header_right,
        body = body,
        version = env!("CARGO_PKG_VERSION"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// unseal_init_page
// First-run initialization form (choose share/threshold counts).
// ─────────────────────────────────────────────────────────────────────────────
pub fn unseal_init_page(error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>Initialize EasyVault</h1>\
         <p class=\"muted\">This generates the master key and splits it into unseal shares. \
         It runs once. The shares are shown only on the next screen — save them.</p>{err}\
         <form method=\"post\" action=\"/gui/unseal/init\">\
         <label>Number of key shares</label><input name=\"shares\" type=\"number\" min=\"1\" value=\"5\">\
         <label>Shares required to unseal (threshold)</label><input name=\"threshold\" type=\"number\" min=\"1\" value=\"3\">\
         <button type=\"submit\">Initialize</button></form></div>"
    );
    layout("Initialize", None, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// unseal_shares_page
// One-time display of the generated unseal shares (must be saved now).
// ─────────────────────────────────────────────────────────────────────────────
pub fn unseal_shares_page(keys: &[String], threshold: usize) -> String {
    let mut list = String::new();
    for (i, k) in keys.iter().enumerate() {
        list.push_str(&format!(
            "<div class=\"kv\" style=\"margin-bottom:8px\"><div class=\"k\">Share {}</div>\
             <div class=\"v\" style=\"font-family:ui-monospace,monospace;word-break:break-all\">{}</div></div>",
            i + 1,
            escape(k),
        ));
    }
    let body = format!(
        "<div class=\"card\"><h1>Save your unseal shares</h1>\
         <div class=\"err\">Copy these now — they are shown only once. You need any {threshold} of them \
         to unseal after every restart. Lose them and the data is unrecoverable; anyone with {threshold} \
         can unseal the instance.</div>{list}\
         <a href=\"/gui/unseal\"><button type=\"button\">I've saved them — continue to unseal</button></a></div>",
        threshold = threshold,
        list = list,
    );
    layout("Unseal shares", None, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// unseal_page
// Sealed-state screen: submit one share at a time with a progress indicator.
// ─────────────────────────────────────────────────────────────────────────────
pub fn unseal_page(progress: usize, threshold: i64, error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>EasyVault is sealed</h1>\
         <p class=\"muted\">Submit unseal shares one at a time. Progress: <strong>{progress} / {threshold}</strong>.</p>{err}\
         <form method=\"post\" action=\"/gui/unseal\">\
         <label>Unseal share</label><input name=\"key\" autofocus required autocomplete=\"off\">\
         <button type=\"submit\">Submit share</button></form></div>",
        progress = progress,
        threshold = threshold,
    );
    layout("Unseal", None, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_page
// First-run page to create the initial master user.
// ─────────────────────────────────────────────────────────────────────────────
pub fn setup_page(error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>Welcome to EasyVault</h1>\
         <h2>Create the master account</h2>{err}\
         <form method=\"post\" action=\"/gui/setup\">\
         <label>Username</label><input name=\"username\" autofocus required>\
         <label>Password</label><input name=\"password\" type=\"password\" required>\
         <p class=\"muted\">At least 8 characters. This account manages all users and vaults.</p>\
         <button type=\"submit\">Create master account</button></form></div>"
    );
    layout("Setup", None, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// login_page
// Username + password login form.
// ─────────────────────────────────────────────────────────────────────────────
pub fn login_page(error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>Sign in</h1>{err}\
         <form method=\"post\" action=\"/gui/login\">\
         <label>Username</label><input name=\"username\" autofocus required>\
         <label>Password</label><input name=\"password\" type=\"password\" required>\
         <button type=\"submit\">Sign in</button></form></div>"
    );
    layout("Sign in", None, &body)
}

/// A vault entry to render in lists: (id, name, optional description).
pub struct VaultListItem {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// dashboard_page
// Authenticated landing: identity, instance seal state, and the user's vaults.
// ─────────────────────────────────────────────────────────────────────────────
pub fn dashboard_page(username: &str, is_master: bool, sealed: bool, vaults: &[VaultListItem]) -> String {
    let role = role_pill(is_master);
    let seal = seal_pill(sealed);
    let seal_note = if sealed {
        "<p class=\"muted\">The instance is sealed — vault and secret operations are blocked \
         until it is unsealed via <code>/v1/sys/unseal</code>.</p>"
    } else {
        ""
    };
    let new_vault = if is_master && !sealed {
        "<a href=\"/gui/vaults/new\"><button type=\"button\">New vault</button></a>"
    } else {
        ""
    };
    let admin_link = if is_master {
        "<p style=\"margin-top:14px\"><a href=\"/gui/users\">Manage users &rarr;</a> &nbsp;·&nbsp; \
         <a href=\"/gui/audit\">Audit log &rarr;</a></p>"
    } else {
        ""
    };
    // Emergency lockdown control (master only, when unsealed).
    let seal_button = if is_master && !sealed {
        "<form method=\"post\" action=\"/gui/seal\" style=\"margin-top:10px\" \
         onsubmit=\"return confirm('Seal the instance? All secret access stops until it is unsealed again.');\">\
         <button type=\"submit\" class=\"btn-danger\">Seal instance</button>\
         <span class=\"muted\"> — drops the master key from memory.</span></form>"
    } else {
        ""
    };

    let vault_rows = if vaults.is_empty() {
        "<p class=\"muted\">No vaults yet.</p>".to_string()
    } else {
        let mut s = String::from("<table><tr><th>Vault</th><th>Description</th></tr>");
        for v in vaults {
            s.push_str(&format!(
                "<tr><td><a href=\"/gui/vaults/{id}\">{name}</a></td><td class=\"muted\">{desc}</td></tr>",
                id = escape(&v.id),
                name = escape(&v.name),
                desc = escape(v.description.as_deref().unwrap_or(""))
            ));
        }
        s.push_str("</table>");
        s
    };

    let body = format!(
        "<div class=\"card\"><h1>Dashboard</h1>\
         <h2>Signed in as {user} {role}</h2>\
         <div class=\"grid\">\
         <div class=\"kv\"><div class=\"k\">Instance</div><div class=\"v\">{seal}</div></div>\
         <div class=\"kv\"><div class=\"k\">Your vaults</div><div class=\"v\">{count}</div></div>\
         </div>{seal_note}{admin_link}{seal_button}</div>\
         <div class=\"card\"><div style=\"display:flex;justify-content:space-between;align-items:center\">\
         <h2 style=\"margin:0\">Vaults</h2>{new_vault}</div>{vault_rows}</div>",
        user = escape(username),
        role = role,
        seal = seal,
        count = vaults.len(),
        seal_note = seal_note,
        admin_link = admin_link,
        seal_button = seal_button,
        new_vault = new_vault,
        vault_rows = vault_rows,
    );
    layout("Dashboard", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// users_page
// Master-only user management: list users and create additional (non-master) ones.
// ─────────────────────────────────────────────────────────────────────────────
pub fn users_page(username: &str, current_user_id: &str, users: &[crate::users::UserListItem], error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let mut rows = String::from("<table><tr><th>Username</th><th>Role</th><th>State</th><th></th></tr>");
    for u in users {
        // No disable control for yourself or other master accounts.
        let action = if u.id == current_user_id || u.is_master {
            String::new()
        } else if u.active {
            format!(
                "<form method=\"post\" action=\"/gui/users/{id}/disable\" style=\"margin:0\">\
                 <button class=\"link\" type=\"submit\">disable</button></form>",
                id = escape(&u.id)
            )
        } else {
            format!(
                "<form method=\"post\" action=\"/gui/users/{id}/enable\" style=\"margin:0\">\
                 <button class=\"link\" type=\"submit\">enable</button></form>",
                id = escape(&u.id)
            )
        };
        rows.push_str(&format!(
            "<tr><td>{name}</td><td>{role}</td><td>{state}</td><td>{action}</td></tr>",
            name = escape(&u.username),
            role = role_pill(u.is_master),
            state = if u.active { "<span class=\"pill ok\">active</span>" } else { "<span class=\"pill warn\">disabled</span>" },
            action = action,
        ));
    }
    rows.push_str("</table>");
    let body = format!(
        "<p><a href=\"/gui/\">&larr; Dashboard</a></p>\
         <div class=\"card\"><h1>Users</h1>{err}{rows}</div>\
         <div class=\"card\"><h2>Add user</h2>\
         <form method=\"post\" action=\"/gui/users\">\
         <label>Username</label><input name=\"username\" required>\
         <label>Password</label><input name=\"password\" type=\"password\" required>\
         <p class=\"muted\">Creates a standard (non-master) user.</p>\
         <button type=\"submit\">Create user</button></form></div>",
        err = err,
        rows = rows,
    );
    layout("Users", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// account_password_page
// Self-service password change form (current + new password).
// ─────────────────────────────────────────────────────────────────────────────
pub fn account_password_page(username: &str, error: Option<&str>, ok: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let note = ok
        .map(|m| format!("<div class=\"err\" style=\"background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok-fg)\">{}</div>", escape(m)))
        .unwrap_or_default();
    let body = format!(
        "<p><a href=\"/gui/\">&larr; Dashboard</a></p>\
         <div class=\"card\"><h1>Change password</h1>{err}{note}\
         <form method=\"post\" action=\"/gui/account/password\">\
         <label>Current password</label><input name=\"current\" type=\"password\" autofocus required>\
         <label>New password</label><input name=\"new_password\" type=\"password\" required>\
         <p class=\"muted\">At least 8 characters. Your vault access is preserved.</p>\
         <button type=\"submit\">Change password</button></form></div>",
        err = err,
        note = note,
    );
    layout("Change password", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// vault_create_page
// Master-only form to create a new vault.
// ─────────────────────────────────────────────────────────────────────────────
pub fn vault_create_page(username: &str, error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>New vault</h1>{err}\
         <form method=\"post\" action=\"/gui/vaults\">\
         <label>Name</label><input name=\"name\" autofocus required>\
         <label>Description</label><input name=\"description\">\
         <button type=\"submit\">Create vault</button>\
         &nbsp;<a href=\"/gui/\">Cancel</a></form></div>"
    );
    layout("New vault", Some(username), &body)
}

/// Inputs for `vault_detail_page` — grouped to keep the call site readable.
pub struct VaultDetail<'a> {
    pub username: &'a str,
    pub vault_id: &'a str,
    pub vault_name: &'a str,
    pub description: &'a str,
    pub secrets: &'a [crate::secrets::SecretListing],
    pub can_read: bool,
    pub can_write: bool,
    pub can_assign: bool,
    pub error: Option<&'a str>,
}

/// Inputs for `vault_settings_page` (management: members + key rotation).
pub struct VaultSettings<'a> {
    pub username: &'a str,
    pub vault_id: &'a str,
    pub vault_name: &'a str,
    pub members: &'a [crate::vault::VaultMember],
    pub current_user_id: &'a str,
    pub error: Option<&'a str>,
}

// ─────────────────────────────────────────────────────────────────────────────
// vault_detail_page
// Vault view, rendered by capability: a reader sees the secret list; a blind
// master sees only the member list; an assigner gets the role grant/revoke UI.
// ─────────────────────────────────────────────────────────────────────────────
pub fn vault_detail_page(d: VaultDetail<'_>) -> String {
    let err = d.error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();

    // Secrets card — only for users who can read this vault.
    let secrets_card = if d.can_read {
        let secret_rows = if d.secrets.is_empty() {
            "<p class=\"muted\">No secrets yet.</p>".to_string()
        } else {
            let mut s = String::from("<table><tr><th>Path</th><th>Version</th><th></th></tr>");
            for sec in d.secrets {
                let href = format!("/gui/vaults/{}/secret?path={}", escape(d.vault_id), urlencode(&sec.path));
                s.push_str(&format!(
                    "<tr><td>{path}</td><td>v{ver}</td><td><a href=\"{href}\">view</a></td></tr>",
                    path = escape(&sec.path),
                    ver = sec.version,
                    href = href,
                ));
            }
            s.push_str("</table>");
            s
        };
        let add = if d.can_write {
            format!(
                "<a href=\"/gui/vaults/{vid}/approles\"><button type=\"button\" class=\"btn-neutral\">AppRoles</button></a> \
                 <a href=\"/gui/vaults/{vid}/tokens\"><button type=\"button\" class=\"btn-neutral\">Tokens</button></a> \
                 <a href=\"/gui/vaults/{vid}/secret/new\"><button type=\"button\">Add secret</button></a>",
                vid = escape(d.vault_id)
            )
        } else {
            String::new()
        };
        format!(
            "<div class=\"card\"><div style=\"display:flex;justify-content:space-between;align-items:center\">\
             <h2 style=\"margin:0\">Secrets</h2>{add}</div>{rows}</div>",
            add = add,
            rows = secret_rows,
        )
    } else {
        "<div class=\"card\"><h2>Secrets</h2>\
         <p class=\"muted\">You manage access to this vault but cannot read its secret contents.</p></div>"
            .to_string()
    };

    let desc_html = if d.description.is_empty() {
        String::new()
    } else {
        format!("<p class=\"muted\">{}</p>", escape(d.description))
    };

    // Managers (master / vault admins) get a Settings link for access, ACL, rotation.
    let settings_btn = if d.can_assign {
        format!(
            "<a href=\"/gui/vaults/{vid}/settings\"><button type=\"button\" class=\"btn-neutral\">Settings</button></a>",
            vid = escape(d.vault_id)
        )
    } else {
        String::new()
    };

    let body = format!(
        "<p><a href=\"/gui/\">&larr; Dashboard</a></p>{err}\
         <div class=\"card\"><div style=\"display:flex;justify-content:space-between;align-items:center\">\
         <h1 style=\"margin:0\">{name}</h1>{settings_btn}</div>{desc}</div>\
         {secrets_card}",
        err = err,
        name = escape(d.vault_name),
        settings_btn = settings_btn,
        desc = desc_html,
        secrets_card = secrets_card,
    );
    layout(d.vault_name, Some(d.username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// vault_settings_page
// Vault management (master / vault admins): member access (assign/revoke),
// network ACL, and key rotation.
// ─────────────────────────────────────────────────────────────────────────────
pub fn vault_settings_page(s: VaultSettings<'_>) -> String {
    let err = s.error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();

    let mut member_rows = String::from("<table><tr><th>User</th><th>Role</th><th>Granted</th><th></th></tr>");
    for m in s.members {
        let revoke = if m.user_id != s.current_user_id {
            format!(
                "<form method=\"post\" action=\"/gui/vaults/{vid}/revoke\" style=\"margin:0\">\
                 <input type=\"hidden\" name=\"user_id\" value=\"{uid}\">\
                 <button class=\"link\" type=\"submit\">revoke</button></form>",
                vid = escape(s.vault_id),
                uid = escape(&m.user_id),
            )
        } else {
            String::new()
        };
        member_rows.push_str(&format!(
            "<tr><td>{user}</td><td>{role}</td><td class=\"muted\">{granted}</td><td>{revoke}</td></tr>",
            user = escape(&m.username),
            role = role_badge(&m.role),
            granted = escape(&m.granted_at),
            revoke = revoke,
        ));
    }
    member_rows.push_str("</table>");

    let assign_form = format!(
        "<form method=\"post\" action=\"/gui/vaults/{vid}/assign\" \
         style=\"display:flex;gap:8px;align-items:flex-end;margin-top:8px\">\
         <div style=\"flex:1\"><label style=\"margin-top:0\">Assign username</label>\
         <input name=\"username\" required></div>\
         <div><label style=\"margin-top:0\">Role</label>\
         <select name=\"role\" style=\"padding:10px 12px;border:1px solid var(--border);border-radius:7px;\
         background:var(--bg);color:var(--fg)\">\
         <option value=\"viewer\">viewer</option>\
         <option value=\"editor\">editor</option>\
         <option value=\"admin\">admin</option></select></div>\
         <button type=\"submit\" style=\"margin:0\">Assign</button></form>",
        vid = escape(s.vault_id)
    );

    let body = format!(
        "<p><a href=\"/gui/vaults/{vid}\">&larr; {name}</a></p>{err}\
         <div class=\"card\"><h1>{name} — settings</h1></div>\
         <div class=\"card\"><h2>Access</h2>{member_rows}{assign_form}</div>\
         <div class=\"card\"><h2>Key rotation</h2>\
         <p class=\"muted\">Generate a new vault key, re-encrypt every secret, and re-wrap the key for \
         all members and live tokens.</p>\
         <form method=\"post\" action=\"/gui/vaults/{vid}/rotate\">\
         <button type=\"submit\" class=\"btn-neutral\">Rotate vault key</button></form></div>",
        vid = escape(s.vault_id),
        name = escape(s.vault_name),
        err = err,
        member_rows = member_rows,
        assign_form = assign_form,
    );
    layout(s.vault_name, Some(s.username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// audit_page
// Master-only audit log viewer; each row shows its HMAC verification status.
// ─────────────────────────────────────────────────────────────────────────────
pub fn audit_page(username: &str, rows: &[crate::audit::AuditRow], verified: &[bool], total: i64, retention_days: i64) -> String {
    let mut body_rows = String::from(
        "<table><tr><th>Time</th><th>Op</th><th>Vault</th><th>Path</th><th>Actor</th>\
         <th>Source IP</th><th>Code</th><th>Integrity</th></tr>",
    );
    if rows.is_empty() {
        body_rows.push_str("<tr><td colspan=\"8\" class=\"muted\">No audit events yet.</td></tr>");
    }
    for (r, ok) in rows.iter().zip(verified.iter()) {
        let integrity = if *ok {
            "<span class=\"pill ok\">ok</span>"
        } else {
            "<span class=\"pill warn\">TAMPERED</span>"
        };
        let actor = r.actor_hash.as_deref().unwrap_or("—");
        let actor_short = if actor.len() > 10 { &actor[..10] } else { actor };
        body_rows.push_str(&format!(
            "<tr><td class=\"muted\">{ts}</td><td>{op}</td><td class=\"muted\">{vault}</td>\
             <td>{path}</td><td class=\"muted\">{actor}</td><td class=\"muted\">{ip}</td>\
             <td>{code}</td><td>{integrity}</td></tr>",
            ts = escape(&r.timestamp),
            op = escape(&r.operation),
            vault = escape(r.vault_id.as_deref().unwrap_or("—")),
            path = escape(r.path.as_deref().unwrap_or("—")),
            actor = escape(actor_short),
            ip = escape(r.source_ip.as_deref().unwrap_or("—")),
            code = r.response_code.unwrap_or(0),
            integrity = integrity,
        ));
    }
    body_rows.push_str("</table>");

    let retention_label = if retention_days <= 0 { "kept forever".to_string() } else { format!("{retention_days} days") };
    let retention_value = if retention_days <= 0 { String::new() } else { retention_days.to_string() };
    let body = format!(
        "<p><a href=\"/gui/\">&larr; Dashboard</a></p>\
         <div class=\"card\"><h1>Audit log</h1>\
         <p class=\"muted\">{total} events total — currently {retention}. Each row is HMAC-signed \
         with a key derived from the master key.</p>\
         <form method=\"post\" action=\"/gui/audit/retention\" \
         style=\"display:flex;gap:8px;align-items:flex-end\">\
         <div><label style=\"margin-top:0\">Retention (days, blank/0 = keep forever)</label>\
         <input name=\"days\" type=\"number\" min=\"0\" value=\"{rvalue}\" placeholder=\"forever\" \
         style=\"width:180px\"></div>\
         <button type=\"submit\" style=\"margin:0\">Save</button></form>\
         <form method=\"post\" action=\"/gui/audit/prune\" style=\"margin-top:10px\">\
         <button type=\"submit\" class=\"btn-neutral\">Prune now</button>\
         <span class=\"muted\"> — delete events older than the retention window.</span></form></div>\
         <div class=\"card\"><h2>Most recent 200 events</h2>{rows}</div>",
        total = total,
        retention = retention_label,
        rvalue = escape(&retention_value),
        rows = body_rows,
    );
    layout("Audit log", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// role_badge
// Render a per-vault role string as a coloured pill.
// ─────────────────────────────────────────────────────────────────────────────
fn role_badge(role: &str) -> String {
    let cls = if role == "viewer" { "warn" } else { "ok" };
    format!("<span class=\"pill {}\">{}</span>", cls, escape(role))
}

// ─────────────────────────────────────────────────────────────────────────────
// tokens_page
// Per-vault API token management: list existing tokens + a create form.
// ─────────────────────────────────────────────────────────────────────────────
pub fn tokens_page(
    username: &str,
    vault_id: &str,
    vault_name: &str,
    tokens: &[crate::tokens::TokenListing],
    can_create: bool,
    error: Option<&str>,
) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();

    let mut rows = String::from(
        "<table><tr><th>Name</th><th>Paths</th><th>IPs</th><th>Expires</th><th>Last used</th><th>State</th><th></th></tr>",
    );
    if tokens.is_empty() {
        rows.push_str("<tr><td colspan=\"7\" class=\"muted\">No tokens yet.</td></tr>");
    }
    for t in tokens {
        let state = if t.revoked {
            "<span class=\"pill warn\">revoked</span>"
        } else {
            "<span class=\"pill ok\">active</span>"
        };
        let revoke = if can_create && !t.revoked {
            format!(
                "<form method=\"post\" action=\"/gui/vaults/{vid}/tokens/{tid}/revoke\" style=\"margin:0\">\
                 <button class=\"link\" type=\"submit\">revoke</button></form>",
                vid = escape(vault_id),
                tid = escape(&t.id),
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr><td>{name}</td><td class=\"muted\">{paths}</td><td class=\"muted\">{ips}</td>\
             <td class=\"muted\">{exp}</td><td class=\"muted\">{used}</td><td>{state}</td><td>{revoke}</td></tr>",
            name = escape(t.display_name.as_deref().unwrap_or("—")),
            paths = escape(&t.allowed_paths),
            ips = escape(if t.allowed_ips == "[]" { "any" } else { &t.allowed_ips }),
            exp = escape(t.expires_at.as_deref().unwrap_or("never")),
            used = escape(t.last_used_at.as_deref().unwrap_or("—")),
            state = state,
            revoke = revoke,
        ));
    }
    rows.push_str("</table>");

    let create = if can_create {
        format!(
            "<div class=\"card\"><h2>Create token</h2>\
             <form method=\"post\" action=\"/gui/vaults/{vid}/tokens\">\
             <label>Name</label><input name=\"display_name\" placeholder=\"ci-deployer\">\
             <label>Allowed paths (one per line, * for all)</label>\
             <textarea name=\"allowed_paths\" rows=\"3\" style=\"width:100%;font-family:ui-monospace,monospace;\
             padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--fg)\">*</textarea>\
             <label>Allowed IPs / CIDRs (one per line, blank = any)</label>\
             <textarea name=\"allowed_ips\" rows=\"2\" style=\"width:100%;font-family:ui-monospace,monospace;\
             padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--fg)\"></textarea>\
             <label>TTL (hours, blank = never expires)</label><input name=\"ttl_hours\" type=\"number\" min=\"1\">\
             <button type=\"submit\">Create token</button></form></div>",
            vid = escape(vault_id)
        )
    } else {
        String::new()
    };

    let body = format!(
        "<p><a href=\"/gui/vaults/{vid}\">&larr; {name}</a></p>{err}\
         <div class=\"card\"><h1>API tokens</h1>{rows}</div>{create}",
        vid = escape(vault_id),
        name = escape(vault_name),
        err = err,
        rows = rows,
        create = create,
    );
    layout("API tokens", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// token_created_page
// One-time display of a freshly minted token's secret value.
// ─────────────────────────────────────────────────────────────────────────────
pub fn token_created_page(username: &str, vault_id: &str, vault_name: &str, raw_token: &str) -> String {
    let body = format!(
        "<div class=\"card\"><h1>Token created</h1>\
         <div class=\"err\">Copy this token now — it will not be shown again.</div>\
         <pre style=\"background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;\
         overflow:auto;color:var(--brand);font-size:15px\">{token}</pre>\
         <p class=\"muted\">Use it as <code>X-Vault-Token</code> against \
         <code>/v1/secret/data/&lt;path&gt;</code>.</p>\
         <a href=\"/gui/vaults/{vid}/tokens\"><button type=\"button\">Done</button></a></div>",
        token = escape(raw_token),
        vid = escape(vault_id),
    );
    let _ = vault_name;
    layout("Token created", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// approles_page
// Per-vault AppRole management: list roles (with role_id) + a create form.
// ─────────────────────────────────────────────────────────────────────────────
pub fn approles_page(
    username: &str,
    vault_id: &str,
    vault_name: &str,
    roles: &[crate::approle::ApproleListing],
    error: Option<&str>,
) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let mut rows = String::from("<table><tr><th>Name</th><th>Role ID</th><th>Paths</th><th>TTL</th><th></th></tr>");
    if roles.is_empty() {
        rows.push_str("<tr><td colspan=\"5\" class=\"muted\">No roles yet.</td></tr>");
    }
    for r in roles {
        rows.push_str(&format!(
            "<tr><td>{name}</td><td class=\"muted\" style=\"font-family:ui-monospace,monospace\">{rid}</td>\
             <td class=\"muted\">{paths}</td><td class=\"muted\">{ttl}</td><td>\
             <form method=\"post\" action=\"/gui/vaults/{vid}/approles/{id}/secret-id\" style=\"display:inline;margin:0\">\
             <button class=\"link\" type=\"submit\">+ secret-id</button></form> &nbsp;\
             <form method=\"post\" action=\"/gui/vaults/{vid}/approles/{id}/delete\" style=\"display:inline;margin:0\">\
             <button class=\"link\" type=\"submit\">delete</button></form></td></tr>",
            name = escape(&r.name),
            rid = escape(&r.role_id),
            paths = escape(&r.allowed_paths),
            ttl = r.token_ttl.map(|s| format!("{}h", s / 3600)).unwrap_or_else(|| "none".into()),
            vid = escape(vault_id),
            id = escape(&r.id),
        ));
    }
    rows.push_str("</table>");

    let body = format!(
        "<p><a href=\"/gui/vaults/{vid}\">&larr; {name}</a></p>{err}\
         <div class=\"card\"><h1>AppRoles</h1>\
         <p class=\"muted\">Machine login: a service exchanges its role_id + secret_id at \
         <code>POST /v1/auth/approle/login</code> for a per-vault token.</p>{rows}</div>\
         <div class=\"card\"><h2>Create role</h2>\
         <form method=\"post\" action=\"/gui/vaults/{vid}/approles\">\
         <label>Name</label><input name=\"name\" placeholder=\"ci-deployer\" required>\
         <label>Allowed paths (one per line, * for all)</label>\
         <textarea name=\"allowed_paths\" rows=\"3\" style=\"width:100%;font-family:ui-monospace,monospace;\
         padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--fg)\">*</textarea>\
         <label>Allowed IPs / CIDRs (one per line, blank = any)</label>\
         <textarea name=\"allowed_ips\" rows=\"2\" style=\"width:100%;font-family:ui-monospace,monospace;\
         padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--fg)\"></textarea>\
         <label>Token TTL (hours, blank = never expires)</label><input name=\"ttl_hours\" type=\"number\" min=\"1\">\
         <button type=\"submit\">Create role</button></form></div>",
        vid = escape(vault_id),
        name = escape(vault_name),
        err = err,
        rows = rows,
    );
    layout("AppRoles", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// approle_secret_page
// One-time display of a freshly issued secret-id (+ the role_id + a usage hint).
// ─────────────────────────────────────────────────────────────────────────────
pub fn approle_secret_page(username: &str, vault_id: &str, vault_name: &str, role_id: &str, secret_id: &str) -> String {
    let _ = vault_name;
    let body = format!(
        "<div class=\"card\"><h1>Secret ID issued</h1>\
         <div class=\"err\">Copy the secret_id now — it will not be shown again.</div>\
         <div class=\"kv\" style=\"margin-bottom:8px\"><div class=\"k\">role_id</div>\
         <div class=\"v\" style=\"font-family:ui-monospace,monospace;word-break:break-all\">{rid}</div></div>\
         <div class=\"kv\"><div class=\"k\">secret_id</div>\
         <div class=\"v\" style=\"font-family:ui-monospace,monospace;word-break:break-all;color:var(--brand)\">{sid}</div></div>\
         <h2 style=\"margin-top:18px\">Login</h2>\
         <pre style=\"padding:14px;overflow:auto\">curl -X POST $ADDR/v1/auth/approle/login \\\n  -d '{{\"role_id\":\"{rid}\",\"secret_id\":\"{sid}\"}}'</pre>\
         <a href=\"/gui/vaults/{vid}/approles\"><button type=\"button\">Done</button></a></div>",
        rid = escape(role_id),
        sid = escape(secret_id),
        vid = escape(vault_id),
    );
    layout("Secret ID", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// secret_new_page
// Form to write a new secret (path + JSON object) into a vault.
// ─────────────────────────────────────────────────────────────────────────────
pub fn secret_new_page(username: &str, vault_id: &str, vault_name: &str, error: Option<&str>, path: &str, data: &str) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<p><a href=\"/gui/vaults/{vid}\">&larr; {name}</a></p>\
         <div class=\"card\"><h1>Add secret</h1>{err}\
         <form method=\"post\" action=\"/gui/vaults/{vid}/secret\">\
         <label>Path</label><input name=\"path\" placeholder=\"db/postgres/password\" value=\"{path}\" required>\
         <label>Data (JSON object)</label>\
         <textarea name=\"data\" rows=\"6\" style=\"width:100%;font-family:ui-monospace,monospace;\
         padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--fg)\" \
         placeholder='{{\"password\": \"s3cr3t\"}}' required>{data}</textarea>\
         <label>Max reads (blank = unlimited; 1 = single-use, burns after one read)</label>\
         <input name=\"max_reads\" type=\"number\" min=\"1\" placeholder=\"unlimited\">\
         <button type=\"submit\">Save secret</button></form></div>",
        vid = escape(vault_id),
        name = escape(vault_name),
        err = err,
        path = escape(path),
        data = escape(data),
    );
    layout("Add secret", Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// secret_view_page
// Show a decrypted secret's current value plus its version history.
// ─────────────────────────────────────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
pub fn secret_view_page(
    username: &str,
    vault_id: &str,
    vault_name: &str,
    path: &str,
    version: i64,
    pretty_json: &str,
    versions: &[crate::secrets::SecretVersion],
    reads_remaining: Option<i64>,
) -> String {
    // Single/N-use badge + note (GUI viewing does not consume; the token API does).
    let use_note = match reads_remaining {
        Some(n) => format!(
            "<p><span class=\"pill warn\">single-use</span> <span class=\"muted\">{n} read(s) remaining over the API — \
             the next API fetch consumes it. Viewing here does not.</span></p>"
        ),
        None => String::new(),
    };
    let mut vrows = String::from("<table><tr><th>Version</th><th>Created</th><th>State</th></tr>");
    for v in versions {
        vrows.push_str(&format!(
            "<tr><td>v{ver}</td><td class=\"muted\">{created}</td><td>{state}</td></tr>",
            ver = v.version,
            created = escape(&v.created_at),
            state = if v.deleted { "<span class=\"pill warn\">deleted</span>" } else { "<span class=\"pill ok\">live</span>" },
        ));
    }
    vrows.push_str("</table>");

    let body = format!(
        "<p><a href=\"/gui/vaults/{vid}\">&larr; {name}</a></p>\
         <div class=\"card\"><h1>{path}</h1>{use_note}<h2>Current value (v{ver})</h2>\
         <pre style=\"background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;\
         overflow:auto;color:var(--fg)\">{json}</pre>\
         <div style=\"display:flex;gap:10px\">\
         <a href=\"/gui/vaults/{vid}/secret/new?path={pathenc}\"><button type=\"button\">New version</button></a>\
         <form method=\"post\" action=\"/gui/vaults/{vid}/secret/delete\" style=\"margin:0\" \
         onsubmit=\"return confirm('Delete this secret and all its versions?');\">\
         <input type=\"hidden\" name=\"path\" value=\"{path}\">\
         <button type=\"submit\" class=\"btn-danger\">Delete secret</button></form></div></div>\
         <div class=\"card\"><h2>Versions</h2>{vrows}</div>",
        vid = escape(vault_id),
        name = escape(vault_name),
        path = escape(path),
        pathenc = urlencode(path),
        ver = version,
        json = escape(pretty_json),
        vrows = vrows,
        use_note = use_note,
    );
    layout(path, Some(username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// notice_page
// Generic single-message page (sealed instance, forbidden, etc.).
// ─────────────────────────────────────────────────────────────────────────────
pub fn notice_page(username: Option<&str>, title: &str, message: &str) -> String {
    let body = format!(
        "<div class=\"card\"><h1>{title}</h1><p class=\"muted\">{msg}</p>\
         <a href=\"/gui/\">&larr; Back to dashboard</a></div>",
        title = escape(title),
        msg = escape(message),
    );
    layout(title, username, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// role_pill / seal_pill
// Small status badges reused across pages.
// ─────────────────────────────────────────────────────────────────────────────
fn role_pill(is_master: bool) -> &'static str {
    if is_master { "<span class=\"pill ok\">master</span>" } else { "<span class=\"pill warn\">user</span>" }
}
fn seal_pill(sealed: bool) -> &'static str {
    if sealed { "<span class=\"pill warn\">sealed</span>" } else { "<span class=\"pill ok\">unsealed</span>" }
}

// ─────────────────────────────────────────────────────────────────────────────
// urlencode
// Minimal percent-encoding for secret paths placed in query strings.
// ─────────────────────────────────────────────────────────────────────────────
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
