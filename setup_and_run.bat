@echo off
:: setup_and_run.bat — Ultimate Web Vuln Analyzer

:: Vérifie si Python est installé
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python n'est pas installé ou non dans PATH.
    pause
    exit /b
)

:: Crée le venv si pas présent
IF NOT EXIST "venv" (
    echo [*] Création du virtual environment...
    python -m venv venv
)

:: Active le venv
echo [*] Activation du virtual environment...
call venv\Scripts\activate.bat

:: Met à jour pip
echo [*] Mise à jour de pip...
python -m pip install --upgrade pip

:: Installe les dépendances
echo [*] Installation des dépendances depuis requirements.txt...
pip install -r requirements.txt

:: Lancement du scanner
echo [*] Lancement du Web Vuln Analyzer...
python vuln_cli.py

:: Fin
echo [*] Exit
pause
