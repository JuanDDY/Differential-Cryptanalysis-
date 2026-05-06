# impossible_differential_cryptanalysis

Carpeta para implementar criptoanalisis diferencial imposible sobre los mismos criptosistemas ya usados en criptoanalisis diferencial clasico.

Objetivo inicial:

- `SPN16`
- `KLEIN`
- `AES`

Idea de organizacion sugerida:

- `spn16_impossible_dc.py`
- `klein_impossible_dc.py`
- `aes_impossible_dc.py`
- `menu.py`

Notas:

- Aqui conviene separar cada criptosistema en su propio archivo.
- El flujo no es igual al criptoanalisis diferencial usual: se buscan diferenciales imposibles y luego se usan para filtrar subclaves.

## Uso rapido

Abrir el menu:

```powershell
python impossible_differential_cryptanalysis\menu.py
```

Estado actual del menu:

- `SPN16`: stub listo para conectar la implementacion real.
- `AES`: stub listo para conectar la implementacion real.
- `KLEIN`: stub listo para conectar la implementacion real.
