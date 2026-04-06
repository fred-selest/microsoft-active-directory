@echo off
echo { > data\settings.json
echo   "menu": { >> data\settings.json
echo     "tool_items": [ >> data\settings.json
echo       {"id": "laps", "label": "LAPS", "endpoint": "tools.laps_passwords", "icon": "🔑", "feature": "FEATURE_LAPS_ENABLED", "enabled": true, "order": 1}, >> data\settings.json
echo       {"id": "laps_mgmt", "label": "Gestion LAPS", "endpoint": "laps_management.laps_dashboard", "icon": "🔐", "feature": "FEATURE_LAPS_ENABLED", "enabled": true, "order": 2}, >> data\settings.json
echo       {"id": "bitlocker", "label": "BitLocker", "endpoint": "tools.bitlocker_keys", "icon": "🔐", "feature": "FEATURE_BITLOCKER_ENABLED", "enabled": true, "order": 3} >> data\settings.json
echo     ] >> data\settings.json
echo   } >> data\settings.json
echo } >> data\settings.json
echo OK - settings.json cree
type data\settings.json
