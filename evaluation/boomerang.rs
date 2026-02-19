// src/lib.rs (o main.rs si prefieres ejecutable)

#[derive(Debug, Clone)]
pub struct SBox {
    pub table: Vec<usize>,
    pub input_size: usize,
    pub output_size: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum BctError {
    #[error("La longitud de S debe ser una potencia de 2.")]
    NoPotenciaDeDos,
    #[error("S debe ser una permutación de 0..N-1.")]
    NoPermutacion,
    #[error("El sbox debe ser biyectivo (input_size == output_size).")]
    NoBiyectivo,
    #[error("El tamaño declarado (2^input_size) no coincide con la tabla.")]
    TamanoDeclaradoNoCoincide,
}

/// Verifica si `s` es una permutación de `0..N-1`.
fn es_permutacion(s: &[usize]) -> bool {
    let n = s.len();
    let mut visto = vec![false; n];
    for &v in s {
        if v >= n || visto[v] {
            return false;
        }
        visto[v] = true;
    }
    true
}

/// Calcula la inversa de una S-box (asumida permutación).
fn inversa(s: &[usize]) -> Vec<usize> {
    let n = s.len();
    let mut s_inv = vec![0usize; n];
    for (x, &y) in s.iter().enumerate() {
        s_inv[y] = x;
    }
    s_inv
}

/// Calcula la Boomerang Connectivity Table (BCT) de una permutación `S` sobre F_2^n.
/// Devuelve una matriz N x N con β_S(a,b).
pub fn bct(s: &[usize]) -> Result<Vec<Vec<u32>>, BctError> {
    let n = s.len();

    // N debe ser potencia de 2
    if !n.is_power_of_two() {
        return Err(BctError::NoPotenciaDeDos);
    }
    // S debe ser una permutación de 0..N-1
    if !es_permutacion(s) {
        return Err(BctError::NoPermutacion);
    }

    // Inversa
    let s_inv = inversa(s);

    // Construir BCT
    let mut beta = vec![vec![0u32; n]; n];
    for a in 0..n {
        for b in 0..n {
            let mut cnt: u32 = 0;
            for x in 0..n {
                // lhs = S^{-1}(S(x) ⊕ b) ⊕ S^{-1}(S(x ⊕ a) ⊕ b)
                let lhs = s_inv[s[x] ^ b] ^ s_inv[s[x ^ a] ^ b];
                if lhs == a {
                    cnt += 1;
                }
            }
            beta[a][b] = cnt;
        }
    }
    Ok(beta)
}

/// Versión que usa la estructura SBox (al estilo de tu Python).
pub fn get_bct(sbox: &SBox) -> Result<Vec<Vec<u32>>, BctError> {
    if sbox.input_size != sbox.output_size {
        return Err(BctError::NoBiyectivo);
    }
    let esperado = 1usize << sbox.input_size;
    if esperado != sbox.table.len() {
        return Err(BctError::TamanoDeclaradoNoCoincide);
    }
    bct(&sbox.table)
}
