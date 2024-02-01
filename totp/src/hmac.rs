// Performs arithmetic to generate HMAC from a message, using a specified hashing algorithm, which is then used to generate a OTP code
use hash::HashFn;

// Padding constants
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Generates a HMAC from a key and messaged, using a specified [hash::HashFn] to compute it
pub fn generate(key: &[u8], message: &[u8], hash: &HashFn) -> Vec<u8> {
    let block_size = hash.get_block_size(); // Block size in bytes from the respective hash function

    // Make key length = block_size
    let block_sized_key = compute_block_sized_key(key, &hash, block_size);

    // Apply XOR 0x36 then XOR 0x5c to each value in block sized key
    let inner_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ IPAD).collect();
    let outer_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ OPAD).collect();

    // Calculate hash(i_key_pad ∥ message)) where ∥ is the concatenation operator, and hash is the hash function specified by options
    let digest: Vec<u8> = hash
        .digest(&concat(inner_key_pad, message.to_vec()));
    // Output hash(o_key_pad ∥ hash(i_key_pad ∥ message)) where ∥ is the concatenation operator, and hash is the hash function specified by options
    hash.digest(&concat(outer_key_pad, digest))
}

/// Calculates the key to be used to create the output
fn compute_block_sized_key(key: &[u8], hash: &HashFn, block_size: usize) -> Vec<u8> {
    // If the key is too long, hash it first (this will always result in an output <= block_size)
    if key.len() > block_size {
        hash.digest(&key.to_vec())
    } else if key.len() < block_size {
        // If the key is too short, pad with 0s to fill it
        pad(key, block_size)
    } else {
        // If the key is exactly the right length, return as is
        key[..].to_vec()
    }
}

/// Increases length of key vector to block_size, padding with 0s
#[inline]
fn pad(key: &[u8], block_size: usize) -> Vec<u8> {
    // Panics if too large
    // Converted to vector, as array sizes are immutable
    let mut pad = key[..].to_vec();
    // Pads to right, filling with 0s
    pad.resize(block_size, 0);
    pad
}

/// Provides an easier to read interface for concatenation of 2 vectors
#[inline]
fn concat(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    vec![a, b].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_hmac() {
        let mac = generate(b"key", b"Primm", &HashFn::SHA1);
        assert_eq!(
            mac,
            vec![
                203, 50, 188, 168, 102, 194, 103, 213, 122, 33, 67, 152, 75, 183, 227, 89, 0, 149,
                161, 215
            ]
        )
    }

    #[test]
    fn empty_hmac() {
        let mac = generate(b"", b"", &HashFn::SHA1);
        assert_eq!(
            mac,
            vec![
                251, 219, 29, 27, 24, 170, 108, 8, 50, 75, 125, 100, 183, 31, 183, 99, 112, 105,
                14, 29
            ]
        )
    }

    #[test]
    fn padding_key() {
        assert_eq!(pad(&[20, 82], 8), vec![20, 82, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn padding_key_shrink() {
        assert_eq!(pad(&[20, 82], 1), vec![20]);
    }
}
