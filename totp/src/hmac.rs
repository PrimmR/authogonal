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
    let digest: Vec<u8> = hash.digest(&concat(inner_key_pad, message.to_vec()));
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
    // Panics if key length over size to pad to
    if key.len() > block_size {
        panic!("Attempt to pad key under original size")
    }
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
    fn empty_hmac_sha1() {
        let mac = generate(b"", b"", &HashFn::SHA1);
        assert_eq!(
            mac,
            vec![
                0xfb, 0xdb, 0x1d, 0x1b, 0x18, 0xaa, 0x6c, 0x08, 0x32, 0x4b, 0x7d, 0x64, 0xb7, 0x1f,
                0xb7, 0x63, 0x70, 0x69, 0x0e, 0x1d
            ]
        )
    }

    #[test]
    fn regular_hmac_sha1() {
        let mac = generate(b"key", b"messages", &HashFn::SHA1);
        assert_eq!(
            mac,
            vec![
                0x6d, 0x07, 0x2b, 0xfe, 0x36, 0xc5, 0xa3, 0xfb, 0x99, 0xd3, 0x47, 0xf2, 0x74, 0xa9,
                0x81, 0x1c, 0x34, 0xce, 0x50, 0xad
            ]
        )
    }

    #[test]
    fn empty_hmac_sha256() {
        let mac = generate(b"", b"", &HashFn::SHA256);
        assert_eq!(
            mac,
            vec![
                0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3,
                0x5f, 0xc5, 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53, 0xc6, 0xc7, 0x12, 0x14,
                0x42, 0x92, 0xc5, 0xad
            ]
        )
    }

    #[test]
    fn regular_hmac_sha256() {
        let mac = generate(b"key", b"messages", &HashFn::SHA256);
        assert_eq!(
            mac,
            vec![
                0x0c, 0x96, 0x1d, 0x68, 0xef, 0xb2, 0xb1, 0x60, 0xfb, 0xcf, 0x4f, 0xa9, 0xbf, 0x5a,
                0x89, 0xd0, 0xb8, 0x47, 0x4a, 0x52, 0x80, 0x19, 0x34, 0x84, 0xc8, 0x74, 0x34, 0x54,
                0xa3, 0xe4, 0x67, 0x71
            ]
        )
    }

    #[test]
    fn empty_hmac_sha512() {
        let mac = generate(b"", b"", &HashFn::SHA512);
        assert_eq!(
            mac,
            vec![
                0xb9, 0x36, 0xce, 0xe8, 0x6c, 0x9f, 0x87, 0xaa, 0x5d, 0x3c, 0x6f, 0x2e, 0x84, 0xcb,
                0x5a, 0x42, 0x39, 0xa5, 0xfe, 0x50, 0x48, 0x0a, 0x6e, 0xc6, 0x6b, 0x70, 0xab, 0x5b,
                0x1f, 0x4a, 0xc6, 0x73, 0x0c, 0x6c, 0x51, 0x54, 0x21, 0xb3, 0x27, 0xec, 0x1d, 0x69,
                0x40, 0x2e, 0x53, 0xdf, 0xb4, 0x9a, 0xd7, 0x38, 0x1e, 0xb0, 0x67, 0xb3, 0x38, 0xfd,
                0x7b, 0x0c, 0xb2, 0x22, 0x47, 0x22, 0x5d, 0x47
            ]
        )
    }

    #[test]
    fn regular_hmac_sha512() {
        let mac = generate(b"key", b"messages", &HashFn::SHA512);
        assert_eq!(
            mac,
            vec![
                0x4d, 0xf4, 0x54, 0x94, 0x76, 0xa5, 0x4e, 0x2b, 0x4a, 0x50, 0x2d, 0xc8, 0xea, 0x25,
                0xe4, 0x14, 0x1c, 0x0d, 0x62, 0xa8, 0xd7, 0xf2, 0x7a, 0x96, 0xee, 0x5d, 0xee, 0x38,
                0x92, 0xcf, 0xe4, 0x57, 0xca, 0x45, 0x89, 0x69, 0x43, 0x5d, 0x8f, 0x9a, 0x77, 0x33,
                0x32, 0xed, 0x35, 0x2d, 0x4d, 0xa3, 0xfc, 0xca, 0xb2, 0xb3, 0xc2, 0xe8, 0x56, 0x2f,
                0xf9, 0x29, 0x6c, 0x05, 0x56, 0xc1, 0x53, 0x87
            ]
        )
    }

    #[test]
    fn padding_key() {
        assert_eq!(pad(&[20, 82], 8), vec![20, 82, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn padding_key_shrink() {
        pad(&[20, 82], 1);
    }
}
