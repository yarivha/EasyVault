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

/// Shared CSS for every page.
const STYLE: &str = "\
:root{color-scheme:dark}\
*{box-sizing:border-box}\
body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#0e1116;color:#e6edf3}\
header{display:flex;align-items:center;justify-content:space-between;\
padding:14px 22px;background:#161b22;border-bottom:1px solid #30363d}\
header .brand{font-weight:700;letter-spacing:.3px}\
header .brand span{color:#3fb950}\
main{max-width:880px;margin:40px auto;padding:0 22px}\
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;margin-bottom:20px}\
h1{font-size:22px;margin:0 0 6px}\
h2{font-size:16px;margin:0 0 14px;color:#9da7b3}\
label{display:block;margin:14px 0 6px;font-size:13px;color:#9da7b3}\
input{width:100%;padding:10px 12px;border:1px solid #30363d;border-radius:7px;\
background:#0e1116;color:#e6edf3;font-size:14px}\
button{margin-top:18px;padding:10px 18px;border:0;border-radius:7px;\
background:#238636;color:#fff;font-weight:600;cursor:pointer;font-size:14px}\
button:hover{background:#2ea043}\
button.link{background:none;color:#58a6ff;padding:0;margin:0;font-weight:400}\
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}\
.err{background:#3d1a1d;border:1px solid #f85149;color:#ffa198;padding:10px 12px;\
border-radius:7px;margin-bottom:8px;font-size:14px}\
.muted{color:#7d8590;font-size:13px}\
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}\
.pill.ok{background:#132e1a;color:#3fb950;border:1px solid #238636}\
.pill.warn{background:#3d2a12;color:#d29922;border:1px solid #9e6a03}\
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}\
.kv{padding:12px 14px;background:#0e1116;border:1px solid #30363d;border-radius:8px}\
.kv .k{font-size:12px;color:#7d8590}.kv .v{font-size:15px;margin-top:2px}\
table{width:100%;border-collapse:collapse;margin-top:10px}\
th{text-align:left;font-size:12px;color:#7d8590;font-weight:600;padding:8px 10px;border-bottom:1px solid #30363d}\
td{padding:9px 10px;border-bottom:1px solid #21262d;font-size:14px;vertical-align:middle}\
tr:last-child td{border-bottom:0}\
textarea{font-family:ui-monospace,monospace}\
code{background:#0e1116;border:1px solid #30363d;border-radius:4px;padding:1px 5px;font-size:13px}";

// ─────────────────────────────────────────────────────────────────────────────
// layout
// Wrap page `body` in the shared shell; `user` adds the header + logout control.
// ─────────────────────────────────────────────────────────────────────────────
pub fn layout(title: &str, user: Option<&str>, body: &str) -> String {
    let header_right = match user {
        Some(name) => format!(
            "<form method=\"post\" action=\"/gui/logout\" style=\"margin:0\">\
             <span class=\"muted\">{}</span> &nbsp;\
             <button class=\"link\" type=\"submit\">Log out</button></form>",
            escape(name)
        ),
        None => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{} · EasyVault</title><style>{}</style></head><body>\
         <header><div class=\"brand\">Easy<span>Vault</span></div><div>{}</div></header>\
         <main>{}</main></body></html>",
        escape(title),
        STYLE,
        header_right,
        body
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
         <button type=\"submit\" style=\"background:#6e2330\">Seal instance</button>\
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
pub fn users_page(username: &str, users: &[crate::users::UserListItem], error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let mut rows = String::from("<table><tr><th>Username</th><th>Role</th><th>State</th></tr>");
    for u in users {
        rows.push_str(&format!(
            "<tr><td>{name}</td><td>{role}</td><td>{state}</td></tr>",
            name = escape(&u.username),
            role = role_pill(u.is_master),
            state = if u.active { "<span class=\"pill ok\">active</span>" } else { "<span class=\"pill warn\">disabled</span>" },
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
    pub members: &'a [crate::vault::VaultMember],
    pub current_user_id: &'a str,
    pub acl_entries: &'a [String],
    pub can_read: bool,
    pub can_write: bool,
    pub can_assign: bool,
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
                "<a href=\"/gui/vaults/{vid}/tokens\"><button type=\"button\" style=\"background:#30363d\">Tokens</button></a> \
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

    // Member listing, with role and (for assigners) a revoke control.
    let mut member_rows = String::from("<table><tr><th>User</th><th>Role</th><th>Granted</th><th></th></tr>");
    for m in d.members {
        let revoke = if d.can_assign && m.user_id != d.current_user_id {
            format!(
                "<form method=\"post\" action=\"/gui/vaults/{vid}/revoke\" style=\"margin:0\">\
                 <input type=\"hidden\" name=\"user_id\" value=\"{uid}\">\
                 <button class=\"link\" type=\"submit\">revoke</button></form>",
                vid = escape(d.vault_id),
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

    // Assign form (username + role) for master / vault admins.
    let assign_form = if d.can_assign {
        format!(
            "<form method=\"post\" action=\"/gui/vaults/{vid}/assign\" \
             style=\"display:flex;gap:8px;align-items:flex-end;margin-top:8px\">\
             <div style=\"flex:1\"><label style=\"margin-top:0\">Assign username</label>\
             <input name=\"username\" required></div>\
             <div><label style=\"margin-top:0\">Role</label>\
             <select name=\"role\" style=\"padding:10px 12px;border:1px solid #30363d;border-radius:7px;\
             background:#0e1116;color:#e6edf3\">\
             <option value=\"viewer\">viewer</option>\
             <option value=\"editor\">editor</option>\
             <option value=\"admin\">admin</option></select></div>\
             <button type=\"submit\" style=\"margin:0\">Assign</button></form>",
            vid = escape(d.vault_id)
        )
    } else {
        String::new()
    };

    let desc_html = if d.description.is_empty() {
        String::new()
    } else {
        format!("<p class=\"muted\">{}</p>", escape(d.description))
    };

    // Network ACL card (assigners only): a textarea of IP/CIDR entries.
    let acl_card = if d.can_assign {
        let current = d.acl_entries.join("\n");
        format!(
            "<div class=\"card\"><h2>Network ACL</h2>\
             <p class=\"muted\">Restrict which client IPs/subnets may use this vault's tokens. \
             Blank = no restriction.</p>\
             <form method=\"post\" action=\"/gui/vaults/{vid}/acl\">\
             <textarea name=\"entries\" rows=\"3\" style=\"width:100%;font-family:ui-monospace,monospace;\
             padding:10px;border:1px solid #30363d;border-radius:7px;background:#0e1116;color:#e6edf3\" \
             placeholder=\"10.0.0.0/8&#10;1.2.3.4\">{current}</textarea>\
             <button type=\"submit\">Save ACL</button></form></div>",
            vid = escape(d.vault_id),
            current = escape(&current),
        )
    } else {
        String::new()
    };

    // Rotate-key control (assigners only).
    let rotate = if d.can_assign {
        format!(
            "<form method=\"post\" action=\"/gui/vaults/{vid}/rotate\" style=\"margin-top:14px\">\
             <button type=\"submit\" style=\"background:#30363d\">Rotate vault key</button>\
             <span class=\"muted\"> — re-encrypts all secrets and re-wraps keys.</span></form>",
            vid = escape(d.vault_id)
        )
    } else {
        String::new()
    };

    let body = format!(
        "<p><a href=\"/gui/\">&larr; Dashboard</a></p>{err}\
         <div class=\"card\"><h1>{name}</h1>{desc}</div>\
         {secrets_card}\
         <div class=\"card\"><h2>Access</h2>{member_rows}{assign_form}{rotate}</div>\
         {acl_card}",
        err = err,
        name = escape(d.vault_name),
        desc = desc_html,
        secrets_card = secrets_card,
        member_rows = member_rows,
        assign_form = assign_form,
        rotate = rotate,
        acl_card = acl_card,
    );
    layout(d.vault_name, Some(d.username), &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// audit_page
// Master-only audit log viewer; each row shows its HMAC verification status.
// ─────────────────────────────────────────────────────────────────────────────
pub fn audit_page(username: &str, rows: &[crate::audit::AuditRow], verified: &[bool]) -> String {
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
    let body = format!(
        "<p><a href=\"/gui/\">&larr; Dashboard</a></p>\
         <div class=\"card\"><h1>Audit log</h1>\
         <p class=\"muted\">Most recent 200 events. Each row is HMAC-signed with a key derived \
         from the master key.</p>{rows}</div>",
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
             padding:10px;border:1px solid #30363d;border-radius:7px;background:#0e1116;color:#e6edf3\">*</textarea>\
             <label>Allowed IPs / CIDRs (one per line, blank = any)</label>\
             <textarea name=\"allowed_ips\" rows=\"2\" style=\"width:100%;font-family:ui-monospace,monospace;\
             padding:10px;border:1px solid #30363d;border-radius:7px;background:#0e1116;color:#e6edf3\"></textarea>\
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
         <pre style=\"background:#0e1116;border:1px solid #30363d;border-radius:8px;padding:14px;\
         overflow:auto;color:#3fb950;font-size:15px\">{token}</pre>\
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
         padding:10px;border:1px solid #30363d;border-radius:7px;background:#0e1116;color:#e6edf3\" \
         placeholder='{{\"password\": \"s3cr3t\"}}' required>{data}</textarea>\
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
pub fn secret_view_page(
    username: &str,
    vault_id: &str,
    vault_name: &str,
    path: &str,
    version: i64,
    pretty_json: &str,
    versions: &[crate::secrets::SecretVersion],
) -> String {
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
         <div class=\"card\"><h1>{path}</h1><h2>Current value (v{ver})</h2>\
         <pre style=\"background:#0e1116;border:1px solid #30363d;border-radius:8px;padding:14px;\
         overflow:auto;color:#e6edf3\">{json}</pre>\
         <div style=\"display:flex;gap:10px\">\
         <a href=\"/gui/vaults/{vid}/secret/new?path={pathenc}\"><button type=\"button\">New version</button></a>\
         <form method=\"post\" action=\"/gui/vaults/{vid}/secret/delete\" style=\"margin:0\">\
         <input type=\"hidden\" name=\"path\" value=\"{path}\">\
         <button type=\"submit\" style=\"background:#6e2330\">Delete</button></form></div></div>\
         <div class=\"card\"><h2>Versions</h2>{vrows}</div>",
        vid = escape(vault_id),
        name = escape(vault_name),
        path = escape(path),
        pathenc = urlencode(path),
        ver = version,
        json = escape(pretty_json),
        vrows = vrows,
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
