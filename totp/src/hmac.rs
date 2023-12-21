// Performs arithmetic to generate HMAC from a message

use crate::key::CodeOptions;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

pub fn generate(key: &[u8], message: &[u8], options: CodeOptions) -> Vec<u8> {
    let block_size = options.hash.get_block_size(); // Block size in bytes
                                                    // let output_size = 40; // Always truncated

    let block_sized_key = compute_block_sized_key(key, options, block_size);

    let input_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ IPAD).collect();
    let output_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ OPAD).collect();

    let digest: Vec<u8> = options
        .hash
        .digest(&concat(input_key_pad, message.to_vec()));
    options.hash.digest(&concat(output_key_pad, digest))
}

fn compute_block_sized_key(key: &[u8], options: CodeOptions, block_size: usize) -> Vec<u8> {
    if key.len() > block_size {
        options.hash.digest(&key.to_vec())
    } else if key.len() < block_size {
        pad(key, block_size)
    } else {
        key[..].to_vec()
    }
}

fn pad(key: &[u8], block_size: usize) -> Vec<u8> {
    // Panics if too large
    let mut pad = key[..].to_vec();
    // Pads to right
    pad.resize(block_size, 0);
    pad
}

fn concat(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    vec![a, b].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_hmac() {
        let mac = generate(b"key", b"Primm", Default::default());
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
        let mac = generate(b"", b"", Default::default());
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
