//! Shared R5 probe fixture: secrets in every R3 + R4 shape and the JSON string walker.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

/// Substrings that must never appear in any output string.
pub const NEEDLES: &[&str] = &[
    "probe_",
    "probesecret",
    "hunter2",
    "mysecretpassword",
    "550e8400",
    "e29b-41d4",
    "hf_a1b2",
    "a1b2c3d4",
    "correct-horse",
    "battery-staple",
    "sk-live",
    "secretpw9",
    "theme=dark",
    "apikey ",
    "longlowercasesecrettokenvalue",
    "abcdefghijklmnopqrstuvwxyz",
    "s3cr3t",
];

/// Argv shapes covering R3 + R4 (all stay in `args`, so a leak is directly visible).
pub fn probe_args() -> Vec<String> {
    [
        "OPTS=-pPROBE_OPTS_P",
        "JAVA_OPTS=-Dapi.key=PROBE_JAVA_OPTS",
        "-c",
        "sh -c 'npx mcp --token PROBE_SHELL_INNER'",
        "--token:PROBE_COLON_B64=",
        "--header=Authorization:Bearer",
        "PROBE_HDR_EQ_SPLIT",
        "--header",
        "Authorization:",
        "Bearer",
        "PROBE_HDR_SPLIT3",
        "--auth",
        "Bearer",
        "PROBE_AUTH_BEARER3",
        "Bearer",
        "PROBE_BEARER_PAIR",
        "/p:hunter2",
        "/p:mysecretpassword",
        "/p:secretpw9",
        "/t:probesecretwintok",
        "/key:probesecretwinkey",
        "/auth:probesecretwinauth",
        "/pass:probesecretwinpass",
        "/pwd:probesecretwinpwd",
        "probesecretlowercasetokenabcdef",
        "longlowercasesecrettokenvalue",
        "abcdefghijklmnopqrstuvwxyz",
        "550e8400-e29b-41d4-a716-446655440000",
        "hf_a1b2c3d4_e5f6g7h8_i9j0k1l2",
        "correct-horse-battery-staple",
        "MYSQL_PWD=probesecretmysql",
        "BEARER=probesecretbearer",
        "GITHUB_PAT=probesecretghpat",
        "JWT=probesecretjwtval",
        "API_SIG=probesecretsigval",
        "{ \"api_key\": \"probesecretjsonak\" }",
        "{ \"pass\": \"probesecretjsonpw\" }",
        "{ \"auth\": \"probesecretjsonau\" }",
        "--config={ \"api_key\": \"probesecretjfs\" }",
        "-H",
        "Cookie: theme=dark; sid=550e8400-e29b-41d4-a716-446655440000",
        "-H",
        "Authorization: ApiKey probesecretcustomscheme",
        "-H",
        "X-Key: probesecretxkey",
        "-H",
        "X-Api_Key: probesecretxak3",
        "--header",
        "X-Auth: probesecretxauth",
        "https://example.com/cb?code=probesecretoauthcode&pwd=probesecreturlpwd",
        "https://alice:PROBE_URL_PW@example.com/mcp",
        "https://alice%3aprobesecret%40example.com/mcp",
        "https://hooks.slack.com/services/probesecretpathseg1234",
        "--PROBE_UNSAFE_LHS_SECRET=1",
        "--sk-live-PROBE_SK_LHS_SECRET=",
        "-a",
        "probesecretredis",
        "-pPROBE_GLUED",
        "--password=PROBE_PW_EQ",
        "--API-KEY=PROBE_UPPER",
        "-uPROBE_USER",
        "Zm9vYmFyYmF6cXV4PROBE_B64",
        "s3cr3t-value-x",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

pub fn probe_command_lines() -> Vec<String> {
    let mut v: Vec<String> = [
        "sh -c \"MYSQL_PWD=probesecretshellenv mysql -h db\"",
        "bash -lc 'npx some-mcp --token PROBE_SHELL_CMD'",
        "sh -c \"sh -c 'npx mcp --token PROBE_NESTED'\"",
        "powershell -Command \"npx mcp --api-key PROBE_PS\"",
        "sqlcmd /p:hunter2 /t:probesecretwintok",
        "node /srv/app/probesecretlowercasetokenabcdef.js --token PROBE_NODE mcp",
        "npx -y @scope/pkg@1.2.3 --port 8080 probesecretlowercasetokenabcdef",
        "redis-cli -a probesecretredis mcp",
        "curl -H 'Cookie: theme=dark; sid=550e8400-e29b-41d4-a716-446655440000' https://x.example/mcp?code=probesecretoauthcode",
        "tool --PROBE_UNSAFE_LHS_SECRET=1 --sk-live-PROBE_SK_LHS_SECRET=",
        "mcp-server correct-horse-battery-staple hf_a1b2c3d4_e5f6g7h8_i9j0k1l2",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let args = probe_args();
    v.push(format!("mcp-server {}", args.join(" ")));
    v
}

pub fn walk(v: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::String(s) => out.push((path.to_string(), s.clone())),
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk(x, &format!("{path}[{i}]"), out);
            }
        }
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                out.push((format!("{path}.<key>"), k.clone()));
                walk(x, &format!("{path}.{k}"), out);
            }
        }
        _ => {}
    }
}

pub fn assert_no_needles(label: &str, v: &serde_json::Value) {
    let mut strings = Vec::new();
    walk(v, label, &mut strings);
    assert!(!strings.is_empty(), "{label}: nothing emitted");
    for (path, s) in strings {
        let low = s.to_ascii_lowercase();
        for n in NEEDLES {
            assert!(!low.contains(n), "{label}: leak of {n:?} at {path}: {s:?}");
        }
    }
}

pub fn write_fixture_home(h: &Path) {
    fs::create_dir_all(h.join(".cursor")).unwrap();
    fs::create_dir_all(h.join(".codex")).unwrap();
    let args = probe_args();
    let cfg = serde_json::json!({"mcpServers": {
        "probe-shapes": {
            "command": "sh -c \"MYSQL_PWD=probesecretshellenv mysql -h db\"",
            "args": args,
            "url": "https://alice:PROBE_URL_PW@example.com/mcp/probesecretpath?code=probesecretoauthcode",
            "headers": {"Authorization": "Bearer PROBE_HDR_VAL", "X-Key": "probesecretxkey"},
            "env": {"API_TOKEN": "PROBE_ENV_TOKEN", "PLAIN": "probesecretplain", "MYSQL_PWD": "probesecretenvpwd"}
        },
        "pkg-sample": {
            "command": "/usr/local/bin/npx",
            "args": ["-y", "@scope/pkg@1.2.3", "--port", "8080", "--token", "PROBE_SAMPLE_TOKEN"]
        }
    }});
    fs::write(h.join(".cursor/mcp.json"), cfg.to_string()).unwrap();
    let mut toml = String::from(
        "[mcp_servers.probe-toml]\ncommand = \"sh -c 'MYSQL_PWD=probesecrettomlenv mysql'\"\nargs = [",
    );
    toml.push_str(
        &probe_args()
            .iter()
            .map(|a| format!("{:?}", a))
            .collect::<Vec<_>>()
            .join(", "),
    );
    toml.push_str("]\nurl = \"https://u:PROBE_TOML_URL@example.com/x?code=probesecrettoml\"\n");
    toml.push_str("[mcp_servers.probe-toml.env]\nAPI_KEY = \"PROBE_TOML_ENV\"\nPLAIN = \"probesecrettomlplain\"\n");
    toml.push_str(
        "[mcp_servers.probe-toml.http_headers]\nAuthorization = \"Bearer PROBE_TOML_HDR\"\n",
    );
    fs::write(h.join(".codex/config.toml"), toml).unwrap();
}
