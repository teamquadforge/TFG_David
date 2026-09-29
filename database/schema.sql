-- Mini-SIEM Sentinel v14 schema
-- If you already had a postgres_data volume, recreate it with:
-- docker compose down -v && docker compose up --build

CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMPTZ DEFAULT NOW(),
    source_type VARCHAR(50) NOT NULL DEFAULT 'unknown',
    source_name VARCHAR(120),
    event_category VARCHAR(80) NOT NULL DEFAULT 'generic',
    event_action VARCHAR(120) NOT NULL DEFAULT 'unknown',
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    src_ip VARCHAR(50),
    src_ip_is_private BOOLEAN,
    user_name VARCHAR(120),
    service VARCHAR(80),
    message TEXT,
    raw_log TEXT NOT NULL,
    tags JSONB DEFAULT '[]'::jsonb,
    risk_score_base INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(event_action);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_time TIMESTAMPTZ DEFAULT NOW(),
    rule_name VARCHAR(160) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    risk_score INTEGER DEFAULT 50,
    src_ip VARCHAR(50),
    user_name VARCHAR(120),
    service VARCHAR(80),
    description TEXT NOT NULL,
    event_count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    mitre_tactic VARCHAR(120),
    mitre_technique VARCHAR(120),
    dedup_key VARCHAR(220),
    status VARCHAR(30) DEFAULT 'open',
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(alert_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    audit_time TIMESTAMPTZ DEFAULT NOW(),
    username TEXT,
    action TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(160) UNIQUE NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    risk_score INTEGER,
    enabled BOOLEAN DEFAULT TRUE,
    mitre_tactic VARCHAR(120),
    mitre_technique VARCHAR(120)
);

INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('SSH brute force', 'Multiple failed SSH logins from the same IP in a short time window.', 'high', 80, 'Credential Access', 'T1110 Brute Force'),
('SSH login after failures', 'A successful SSH login occurred after several failed attempts from the same IP.', 'high', 85, 'Initial Access', 'T1078 Valid Accounts'),
('Root login attempt', 'SSH login attempt targeting the root account.', 'medium', 60, 'Credential Access', 'T1110 Brute Force'),
('Password spraying candidate', 'One source IP attempted authentication against multiple users.', 'medium', 65, 'Credential Access', 'T1110.003 Password Spraying'),
('Web sensitive path access', 'HTTP request to sensitive or commonly abused path.', 'medium', 55, 'Reconnaissance', 'T1595 Active Scanning'),
('Web scan - many 404', 'Many HTTP 404 responses from the same IP in a short time window.', 'medium', 60, 'Reconnaissance', 'T1595 Active Scanning'),
('Container error burst', 'Repeated error-like messages from a container.', 'medium', 50, 'Impact', 'T1499 Endpoint Denial of Service')
ON CONFLICT (rule_name) DO NOTHING;

CREATE TABLE IF NOT EXISTS watchlist (
    id SERIAL PRIMARY KEY,
    value TEXT UNIQUE NOT NULL,
    ioc_type VARCHAR(40) NOT NULL DEFAULT 'ip',
    label TEXT,
    severity VARCHAR(20) DEFAULT 'high',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_watchlist_value ON watchlist(value);

CREATE TABLE IF NOT EXISTS alert_notes (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    username TEXT,
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('IOC watchlist match', 'An event matched an IP or indicator from the local watchlist.', 'high', 90, 'Command and Control', 'T1071 Application Layer Protocol'),
('External root login attempt', 'Root authentication attempt from a public source IP.', 'critical', 95, 'Credential Access', 'T1110 Brute Force'),
('Many events from public IP', 'High activity from a public source IP in a short time window.', 'medium', 58, 'Reconnaissance', 'T1595 Active Scanning')
ON CONFLICT (rule_name) DO NOTHING;


CREATE TABLE IF NOT EXISTS cases (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity VARCHAR(20) DEFAULT 'medium',
    status VARCHAR(30) DEFAULT 'open',
    owner TEXT
);

CREATE TABLE IF NOT EXISTS case_alerts (
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    linked_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS playbooks (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    trigger_rule TEXT,
    severity VARCHAR(20),
    steps JSONB DEFAULT '[]'::jsonb
);

INSERT INTO playbooks (name, trigger_rule, severity, steps) VALUES
('SSH brute force triage', 'SSH brute force', 'high',
 '["Confirmar IP origen y ventana temporal", "Revisar usuarios afectados", "Buscar successful_login posterior", "Añadir IP a watchlist si aplica", "Cerrar como mitigado o abrir caso"]'::jsonb),
('External root login response', 'External root login attempt', 'critical',
 '["Prioridad inmediata", "Validar si root login está permitido", "Revisar auth.log completo", "Bloquear IP origen en firewall", "Rotar credenciales si hubo login correcto", "Abrir incidente"]'::jsonb),
('Web scanning triage', 'Web sensitive path access', 'medium',
 '["Listar rutas solicitadas", "Correlacionar con 404", "Comprobar si hay respuesta 200 en rutas sensibles", "Añadir IP a watchlist", "Documentar evidencia"]'::jsonb),
('IOC match response', 'IOC watchlist match', 'high',
 '["Identificar por qué el IOC está en watchlist", "Buscar todos los eventos de la IP", "Vincular alertas a caso", "Aplicar contención si es IP pública real"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Mini-SIEM v5 Windows endpoint agents and AI/SOC rules
CREATE TABLE IF NOT EXISTS agents (
    id SERIAL PRIMARY KEY,
    agent_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    os_type TEXT NOT NULL DEFAULT 'windows',
    os_version TEXT,
    version TEXT,
    status TEXT DEFAULT 'online',
    last_seen TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_source_name ON events(source_name);

INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('Windows failed logon burst', 'Multiple Windows failed logons from the same source in a short time window.', 'high', 82, 'Credential Access', 'T1110 Brute Force'),
('Windows logon after failures', 'A successful Windows logon occurred after several failed attempts.', 'critical', 90, 'Initial Access', 'T1078 Valid Accounts'),
('Windows audit log cleared', 'The Windows Security audit log was cleared, which may indicate anti-forensics.', 'critical', 96, 'Defense Evasion', 'T1070.001 Clear Windows Event Logs'),
('Microsoft Defender malware detected', 'Microsoft Defender detected malware or unwanted software.', 'critical', 92, 'Execution', 'T1204 User Execution'),
('Windows privileged group change', 'A user was added to a privileged or security-sensitive Windows group.', 'high', 88, 'Persistence', 'T1098 Account Manipulation'),
('Windows local account created', 'A Windows local/domain account was created.', 'high', 78, 'Persistence', 'T1136 Create Account'),
('Windows service installed', 'A new Windows service was installed.', 'high', 78, 'Persistence', 'T1543.003 Windows Service'),
('Windows suspicious process', 'Suspicious process, credential-access string or LOLBin pattern was observed.', 'high', 84, 'Defense Evasion', 'T1218 System Binary Proxy Execution'),
('Suspicious PowerShell activity', 'Suspicious PowerShell script block or encoded command was observed.', 'high', 86, 'Execution', 'T1059.001 PowerShell')
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO playbooks (name, trigger_rule, severity, steps) VALUES
('Windows endpoint compromise triage', 'Windows suspicious process', 'high',
 '["Identificar host, usuario, proceso y command line", "Buscar eventos 4688/Sysmon 1 relacionados", "Revisar conexiones Sysmon 3 o actividad de red", "Aislar endpoint si hay patrón de credenciales o LOLBin", "Crear caso y exportar evidencias"]'::jsonb),
('Windows audit log cleared response', 'Windows audit log cleared', 'critical',
 '["Escalar inmediatamente", "Comprobar usuario que limpió el log", "Revisar otros logs no borrados: System, Defender, Sysmon", "Aislar el equipo si no está justificado", "Abrir incidente de defensa evasiva"]'::jsonb),
('Microsoft Defender malware response', 'Microsoft Defender malware detected', 'critical',
 '["Revisar amenaza detectada, ruta y acción aplicada", "Ejecutar análisis completo", "Comprobar persistencia: servicios, tareas, cuentas", "Mantener evidencia antes de limpiar", "Cerrar con estado de remediación"]'::jsonb),
('Windows brute force response', 'Windows failed logon burst', 'high',
 '["Validar IP origen y usuario objetivo", "Buscar 4624 posterior desde la misma IP", "Bloquear origen si es externo o no esperado", "Revisar exposición RDP/SMB/VPN", "Documentar intento y mitigación"]'::jsonb)
ON CONFLICT (name) DO NOTHING;


-- Mini-SIEM Sentinel v11 Download Guard + Copilot contextual
INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('Download Guard - arxiu sospitós', 'El Download Guard ha trobat scripts, executables, macros o altres elements sensibles dins una descàrrega o arxiu ZIP.', 'high', 84, 'Initial Access', 'T1204 User Execution'),
('Download Guard - executable descarregat', 'S’ha observat una descàrrega executable o potencialment executable al directori de Descàrregues.', 'medium', 68, 'Initial Access', 'T1204 User Execution')
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO playbooks (name, trigger_rule, severity, steps) VALUES
('Download Guard triatge ZIP sospitós', 'Download Guard - arxiu sospitós', 'high',
 '["No executar el fitxer fins completar la revisió", "Comprovar hash SHA256 i ruta", "Revisar extensions internes: exe, ps1, bat, cmd, js, vbs, lnk, scr, msi, dll, docm, xlsm", "Verificar si l’usuari l’ha descarregat d’una font legítima", "Crear incident si l’arxiu s’ha executat o conté múltiples elements sospitosos"]'::jsonb),
('Executable descarregat', 'Download Guard - executable descarregat', 'medium',
 '["Confirmar origen de la descàrrega", "Calcular hash SHA256", "No executar si no és esperat", "Buscar alertes de procés posteriors", "Afegir evidència al cas si aplica"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Mini-SIEM Sentinel v13 additions: demo mode, FIM, posture, retention and Sigma-lite
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO settings (key, value) VALUES
('retention_events_days', '30'),
('retention_audit_days', '90')
ON CONFLICT (key) DO NOTHING;

INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('Download Guard dangerous archive', 'ZIP or archive in Downloads contains executable, script, macro, shortcut or suspicious naming patterns.', 'high', 82, 'Initial Access', 'T1204 User Execution'),
('Download Guard executable observed', 'Executable-like file observed in Downloads folder.', 'medium', 55, 'Initial Access', 'T1204 User Execution'),
('Hosts file modified', 'Windows hosts file changed, which can be used to redirect traffic or block security services.', 'critical', 88, 'Defense Evasion', 'T1565 Data Manipulation'),
('Autorun persistence candidate', 'Startup folder or autorun-like persistence item observed.', 'high', 78, 'Persistence', 'T1060 Registry Run Keys / Startup Folder'),
('Suspicious file created', 'Script or executable-like file created in a monitored user folder.', 'medium', 55, 'Execution', 'T1204 User Execution')
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO playbooks (name, trigger_rule, severity, steps) VALUES
('Download Guard response', 'Download Guard dangerous archive', 'high',
 '["No executar el fitxer", "Revisar entrades del ZIP i doble extensió", "Calcular hash SHA256", "Comprovar si l’usuari l’ha descarregat voluntàriament", "Eliminar o aïllar el fitxer si no és confiable", "Crear incident si hi ha execució posterior"]'::jsonb),
('File Integrity response', 'Hosts file modified', 'critical',
 '["Escalar com a possible manipulació local", "Comparar hash anterior i nou", "Revisar processos i usuaris al voltant del canvi", "Restaurar fitxer hosts si el canvi no està justificat", "Buscar persistència i connexions sospitoses"]'::jsonb),
('Autorun persistence triage', 'Autorun persistence candidate', 'high',
 '["Identificar ruta d’autoarrencada", "Verificar signatura i origen del fitxer", "Relacionar amb descàrregues o PowerShell", "Desactivar element si és sospitós", "Crear incident amb timeline"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Mini-SIEM Sentinel v14 additions: Telegram notifications and lightweight EDR response.
CREATE TABLE IF NOT EXISTS notification_history (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    channel TEXT NOT NULL DEFAULT 'telegram',
    severity VARCHAR(20) DEFAULT 'info',
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    title TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    destination TEXT,
    error TEXT,
    payload JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_notification_history_created ON notification_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_history_alert ON notification_history(alert_id);

CREATE TABLE IF NOT EXISTS edr_actions (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    executed_at TIMESTAMPTZ,
    requested_by TEXT,
    agent_id TEXT,
    hostname TEXT,
    action_type TEXT NOT NULL,
    target_path TEXT,
    target_hash TEXT,
    requested_reason TEXT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    quarantine_path TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_edr_actions_status ON edr_actions(status);
CREATE INDEX IF NOT EXISTS idx_edr_actions_agent ON edr_actions(agent_id, hostname);
CREATE INDEX IF NOT EXISTS idx_edr_actions_created ON edr_actions(created_at DESC);

CREATE TABLE IF NOT EXISTS quarantine_records (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    agent_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256 TEXT,
    reason TEXT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
    status TEXT DEFAULT 'quarantined',
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_quarantine_records_created ON quarantine_records(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_records_sha256 ON quarantine_records(sha256);

INSERT INTO settings (key, value) VALUES
('telegram_enabled', 'false'),
('telegram_bot_token', ''),
('telegram_chat_id', ''),
('telegram_min_severity', 'critical'),
('edr_quarantine_enabled', 'true')
ON CONFLICT (key) DO NOTHING;

INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('EDR quarantine executed', 'The Windows agent moved a suspicious file to local quarantine after analyst approval.', 'medium', 45, 'Response', 'Containment'),
('EDR suspicious chain correlated', 'Multiple endpoint signals suggest a possible attack chain that should be investigated as an incident.', 'critical', 95, 'Multiple', 'Attack Chain')
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO playbooks (name, trigger_rule, severity, steps) VALUES
('EDR quarentena segura', 'EDR quarantine executed', 'medium',
 '["Confirmar que el fitxer era sospitós", "Revisar hash SHA256 i ruta original", "No eliminar la quarantena fins acabar la investigació", "Afegir el hash a watchlist si es confirma", "Documentar l’acció a l’incident"]'::jsonb),
('Notificació crítica Telegram', 'Microsoft Defender malware detected', 'critical',
 '["Confirmar recepció de l’avís", "Obrir el SOC", "Revisar alerta i evidències", "Crear incident si hi ha execució o persistència", "Aplicar playbook i tancar amb justificació"]'::jsonb)
ON CONFLICT (name) DO NOTHING;


-- v15 Home Network Telemetry + Threat Intelligence
CREATE TABLE IF NOT EXISTS network_devices (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(80) UNIQUE,
    mac_address VARCHAR(40),
    hostname VARCHAR(160),
    source_name VARCHAR(160),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    event_count INTEGER DEFAULT 1,
    risk_score INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_network_devices_last_seen ON network_devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_network_devices_mac ON network_devices(mac_address);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id SERIAL PRIMARY KEY,
    kind VARCHAR(80) NOT NULL,
    value TEXT NOT NULL,
    result JSONB DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(kind, value)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_cache_updated ON threat_intel_cache(updated_at DESC);

INSERT INTO rules (rule_name, description, severity, risk_score, mitre_tactic, mitre_technique) VALUES
('Network new device observed', 'Detecta dispositius nous a la xarxa domèstica mitjançant DHCP/syslog.', 'medium', 52, 'Discovery', 'T1016 System Network Configuration Discovery'),
('Router admin login activity', 'Detecta intents o activitat d’autenticació al router.', 'high', 78, 'Initial Access', 'T1078 Valid Accounts'),
('Router firewall block burst', 'Molts bloquejos de firewall en una finestra temporal curta.', 'high', 82, 'Reconnaissance', 'T1595 Active Scanning'),
('DNS suspicious query', 'Consultes DNS cap a dominis sospitosos o dinàmics.', 'medium', 65, 'Command and Control', 'T1071 Application Layer Protocol'),
('Network scan candidate', 'Patrons de possible escaneig o reconeixement a la xarxa.', 'high', 78, 'Reconnaissance', 'T1046 Network Service Discovery'),
('AbuseIPDB high-risk IP observed', 'IP pública amb reputació dolenta segons AbuseIPDB.', 'high', 85, 'Command and Control', 'T1071 Application Layer Protocol'),
('VirusTotal malicious hash observed', 'Hash de fitxer marcat com maliciós per VirusTotal.', 'critical', 95, 'Initial Access', 'T1204 User Execution')
ON CONFLICT (rule_name) DO NOTHING;
