# evaluation/fixed_points.py

import numpy as np
from sboxes import SBox

def fixed_ponts(sbox: SBox, square: bool = True, detail: bool = False):
    """
    Cuenta cuántos puntos fijos tiene la S-box (table[i] == i)
    """
    counter = 0

    if square:
        for i, v in enumerate(sbox.table):
            # Parsear v a entero, cabalmente
            if isinstance(v, (str, np.str_)):
                val = int(v, 0)    # interpreta "0x1" como hex
            else:
                val = int(v)

            if val == i:
                # si no pides detail, basta con saber que hay al menos uno
                if not detail:
                    return False
                counter += 1

        # Si pediste detail, devolvemos (hay_o_no, cuántos)
        if detail:
            has_fixed = (counter > 0)
            return has_fixed, counter

        # Si no pediste detail, devolvemos False (ningún punto fijo),
        # o True si no hay ninguno (depende de tu definición original).
        return False  # o True si quieres indicar “ningún punto fijo” como éxito

    else:
        # Si square=False tu función original devolvía siempre False
        return True
