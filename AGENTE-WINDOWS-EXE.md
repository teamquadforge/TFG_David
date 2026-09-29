# MiniSIEM Windows Native Agent v6

Este agente es la pieza que convierte el proyecto en una aplicación real para Windows: se instala como servicio, lee el Visor de eventos y envía eventos al backend del Mini-SIEM.

## Qué recoge

- Security: 4624, 4625, 4648, 4672, 4688, 4720, 4726, 4732, 4740, 4768, 4769, 4771, 4776, 1102.
- System: 7045, 7036, 6005, 6006, 6008, 1074.
- Defender: 1116, 1117, 1118, 1119, 1121, 5007.
- PowerShell: 4103, 4104, 4105, 4106.
- Sysmon si está instalado: 1, 3, 7, 10, 11, 12, 13, 22, 23, 24, 25.

## Construir el EXE en Windows

Ejecutar PowerShell como administrador:

```powershell
cd windows-native-agent
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build-exe.ps1 -BackendUrl "http://IP_DEL_SIEM:8000" -AgentToken "CAMBIA_ESTE_TOKEN"
```

Resultado:

```text
dist\MiniSIEMAgent.exe
dist\MiniSIEMAgentService.exe
dist\MiniSIEMAgent-Windows.zip
```

## Instalar en un Windows real

```powershell
cd dist\package
.\install-agent.ps1 -BackendUrl "http://IP_DEL_SIEM:8000" -AgentToken "CAMBIA_ESTE_TOKEN"
```

## Demo controlada

```powershell
.\install-agent.ps1 -BackendUrl "http://IP_DEL_SIEM:8000" -AgentToken "CAMBIA_ESTE_TOKEN" -DemoOnce
```

## Dónde queda instalado

- Binarios: `C:\Program Files\MiniSIEMAgent`
- Configuración y cola local: `C:\ProgramData\MiniSIEMAgent`
- Servicio Windows: `MiniSIEMAgent`

## Seguridad

- Cambiar siempre `WINDOWS_AGENT_TOKEN` en el servidor.
- Usar HTTPS en red real.
- Ejecutar como servicio con mínimos privilegios cuando la demo ya esté validada.
- No enviar XML completo salvo que sea necesario (`include_raw_xml=false` por defecto).
