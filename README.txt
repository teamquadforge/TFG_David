Mini-SIEM Sentinel v13 · Versió TFG completa
============================================

Aquesta versió està enfocada a defensa final del TFG: SIEM personal amb agent Windows, logs reals,
Download Guard, File Integrity Monitoring, postura de seguretat, alertes explicables, Mode demo,
MITRE coverage, incidents, playbooks, auditoria i configuració de retenció.

Arrencada:
  docker compose down -v
  docker compose build --no-cache
  docker compose up

URLs:
  Landing: http://localhost/landing.html
  SOC:     http://localhost/login.html
  API:     http://localhost:8000

Agent Windows:
  1. Obre la landing i descarrega l'agent Windows.
  2. Extreu el ZIP.
  3. Executa AGENTE-WINDOWS-INSTALADOR\Setup-MiniSIEMAgent.cmd com administrador.
  4. Backend URL: http://127.0.0.1:8000
  5. Token: dev-windows-agent-token

Novetats v13:
  - Mode demo TFG integrat: Defender crític, PowerShell sospitós, ZIP perillós, hosts modificat i incident complet.
  - Alertes explicables: per què ha saltat, evidències, MITRE, risc i passos recomanats.
  - Esdeveniments amb etiquetes humanes en català.
  - File Integrity Monitoring: hosts, Startup, Desktop, Documents i fitxers executables/scripts.
  - Download Guard millorat: ZIP, doble extensió, scripts, macros, executables i noms sospitosos.
  - Postura de seguretat: Defender, Firewall, BitLocker, UAC, PowerShell logging i Sysmon.
  - Cobertura MITRE ATT&CK.
  - Configuració de retenció i neteja.
  - Arquitectura i manual d'ús dins del dashboard.

Flux recomanat per la defensa:
  1. Obre la landing i explica el producte.
  2. Entra al SOC.
  3. Obre Mode demo TFG i genera "Incident complet".
  4. Ves a Alertes, selecciona una alerta high/critical i mostra l'explicació.
  5. Pregunta a l'Assistent SOC si t'hauries de preocupar.
  6. Ves a Incidents i mostra el timeline.
  7. Ves a Playbooks i mostra resposta guiada.
  8. Ves a Auditoria i mostra traçabilitat.
  9. Ves a Arquitectura i explica el disseny.

Seguretat:
  - No executa malware real.
  - L'agent no obre ports ni permet execució remota.
  - La comunicació agent -> backend usa token.
  - Les dades són locals al desplegament.
  - Canvia SECRET_KEY i WINDOWS_AGENT_TOKEN abans d'una demo pública.
