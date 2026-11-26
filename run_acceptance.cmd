@echo off
setlocal
cd /d "%~dp0" || exit /b 1

set "TRACK4_TOOLKIT=%~dp0..\track4-toolkit"
set "TRACK4_ENTRY=%~dp0track4_service.py"
set "TRACK4_STATE_DIR="

if not exist "%TRACK4_TOOLKIT%\validate.py" (
    echo FAIL: toolkit validator is missing from "%TRACK4_TOOLKIT%"
    exit /b 1
)

for %%T in (
    test_protected_read.py
    test_two_node_revocation.py
    test_key_rotation.py
    test_signed_rotation.py
    test_rotation_recovery.py
    test_key_backup.py
    key_event_log.py
    operator_workflow.py
    test_detection_scenarios.py
    encrypted_report_demo.py
    test_report_delivery.py
    test_forward_secrecy.py
    test_transfer_rotation.py
    device_reenrollment.py
    test_backup_restore.py
) do (
    echo.
    echo === %%T ===
    py -3.12 "%%T"
    if errorlevel 1 (
        echo FAIL: %%T
        exit /b 1
    )
)

echo.
echo === Labelled public practice events ===
py -3.12 detect_access.py "%TRACK4_TOOLKIT%\practice" --evaluate
if errorlevel 1 (
    echo FAIL: practice evaluation
    exit /b 1
)

echo.
echo === Organizer lost-device validator ===
pushd "%TRACK4_TOOLKIT%" || exit /b 1
py -3.12 validate.py --entry "%TRACK4_ENTRY%"
set "VALIDATOR_EXIT=%ERRORLEVEL%"
popd

if not "%VALIDATOR_EXIT%"=="0" (
    echo FAIL: organizer lost-device validator
    exit /b 1
)

echo.
echo PASS: all local acceptance commands completed successfully