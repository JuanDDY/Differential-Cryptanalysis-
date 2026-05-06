# Differential-Cryptanalysis-

Proyecto con implementaciones de cifrados (SPN16, SPN modular, KLEIN, AES) y utilidades de criptoanalisis diferencial.

## Setup rapido (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Uso basico

```powershell
# tests
python -m unittest discover -s cryptosystems -p "test*.py" -v

# busqueda de diferenciales/caracteristicas en SPN16
python find_characteristics\spn16_characteristic_search.py --delta-in 0x0B00 --rounds 5 --top-k 10
```
