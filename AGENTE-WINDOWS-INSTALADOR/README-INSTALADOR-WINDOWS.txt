Mini-SIEM Sentinel Windows Agent v11

Instal·lació:
1. Clic dret a Setup-MiniSIEMAgent.cmd
2. Executa com a administrador
3. Backend URL: http://127.0.0.1:8000
4. Token: dev-windows-agent-token

Funcions:
- Llegeix esdeveniments reals del Visor d’esdeveniments de Windows.
- Envia heartbeats al SIEM.
- Revisa la carpeta Descàrregues i analitza ZIPs abans que l’usuari els executi.
- Genera alertes si detecta executables, scripts, macros o fitxers sospitosos dins d’un ZIP.

Limitació important:
Aquest agent de TFG no és un EDR amb driver de kernel. Pot detectar, avisar i ajudar a decidir, però no pot garantir bloqueig absolut d’execució sense AppLocker/WDAC/Defender.

Logs de l’agent:
C:\ProgramData\MiniSIEMAgent\agent.log
