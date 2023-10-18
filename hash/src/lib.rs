pub trait Hash {
    const BLOCK_SIZE: usize = 64;

    fn to_vec(&self) -> Vec<u8>;
    fn process_chunks(&self, chunk: &[u8]) -> Self;

    fn digest(self, message: &[u8]) -> Vec<u8>
    where
        Self: Sized + std::ops::Add<Self, Output = Self>,
    {
        // Message length in bits
        let ml: u64 = TryInto::<u64>::try_into(message.len()).unwrap() * 8;
        let mut message = message.to_vec();

        // Pre-processing
        message.push(0x80);

        // message len needs to be multiple of (512-64)/8 = 56
        message = pad_mult(message, 64, 8);
        message.append(&mut u64::to_be_bytes(ml).to_vec());

        // chunk into 512/8= 64 byte chunks
        let chunks = message.chunks(64);

        let hash = chunks.fold(self, |acc, x| acc.process_chunks(x) + acc);

        hash.to_vec()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HashFn {
    SHA1,
    SHA256,
    SHA512,
}

impl HashFn {
    pub fn digest(&self, message: &Vec<u8>) -> Vec<u8> {
        match self {
            Self::SHA1 => sha1::SHA1Hash::new().digest(message),
            Self::SHA256 => sha2::SHA256Hash::new().digest(message),
            Self::SHA512 => sha2::SHA512Hash::new().digest(message),
        }
    }

    pub fn get_block_size(&self) -> usize {
        match self {
            Self::SHA1 => sha1::SHA1Hash::BLOCK_SIZE,
            Self::SHA256 => sha2::SHA256Hash::BLOCK_SIZE,
            Self::SHA512 => sha2::SHA512Hash::BLOCK_SIZE,
        }
    }
}

trait Bits {
    const BITS: u8;
}

impl Bits for u32 {
    const BITS: u8 = Self::BITS as u8;
}
impl Bits for u64 {
    const BITS: u8 = Self::BITS as u8;
}

pub mod sha1 {
    use super::*;

    // SHA1
    #[derive(Debug)]
    pub struct SHA1Hash(u32, u32, u32, u32, u32);

    impl SHA1Hash {
        const H0: u32 = 0x67452301;
        const H1: u32 = 0xEFCDAB89;
        const H2: u32 = 0x98BADCFE;
        const H3: u32 = 0x10325476;
        const H4: u32 = 0xC3D2E1F0;

        pub fn new() -> Self {
            Self(Self::H0, Self::H1, Self::H2, Self::H3, Self::H4)
        }
    }

    impl Hash for SHA1Hash {
        fn to_vec(&self) -> Vec<u8> {
            let mut v = Vec::new();
            v.append(&mut self.0.to_be_bytes().to_vec());
            v.append(&mut self.1.to_be_bytes().to_vec());
            v.append(&mut self.2.to_be_bytes().to_vec());
            v.append(&mut self.3.to_be_bytes().to_vec());
            v.append(&mut self.4.to_be_bytes().to_vec());
            v
        }

        fn process_chunks(&self, chunk: &[u8]) -> SHA1Hash {
            // Convert 64 byte chunks to 16 32-bit big-endian words
            let mut words: Vec<u32> = chunk
                .chunks(4)
                .map(|x| u32::from_be_bytes(x.try_into().unwrap()))
                .collect();

            // Creates 80 long vec
            for i in 16..80 {
                let item = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
                words.push(left_rot(item, 1));
            }

            // Init values
            let mut a = self.0;
            let mut b = self.1;
            let mut c = self.2;
            let mut d = self.3;
            let mut e = self.4;

            for i in 0..80 {
                let (f, k): (u32, u32) = match i {
                    0..=19 => (d ^ (b & (c ^ d)), 0x5A827999), // ((b & c) | (!b & d), 0xfa827999),
                    20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                    _ => (b ^ c ^ d, 0xca62c1d6), // 60..=79
                };

                // Wrapping add keeps number as u32
                let temp = left_rot(a, 5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(words[i]);

                e = d;
                d = c;
                c = left_rot(b, 30);
                b = a;
                a = temp;
            }

            SHA1Hash(a, b, c, d, e)
        }
    }

    impl std::ops::Add for SHA1Hash {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            // Addition that prevents overflows
            Self(
                self.0.wrapping_add(rhs.0),
                self.1.wrapping_add(rhs.1),
                self.2.wrapping_add(rhs.2),
                self.3.wrapping_add(rhs.3),
                self.4.wrapping_add(rhs.4),
            )
        }
    }
}

pub mod sha2 {
    use super::*;

    //SHA256
    #[derive(Debug)]
    pub struct SHA256Hash(u32, u32, u32, u32, u32, u32, u32, u32);

    impl SHA256Hash {
        const H0: u32 = 0x6A09E667;
        const H1: u32 = 0xBB67AE85;
        const H2: u32 = 0x3C6EF372;
        const H3: u32 = 0xA54FF53A;
        const H4: u32 = 0x510E527F;
        const H5: u32 = 0x9B05688C;
        const H6: u32 = 0x1F83D9AB;
        const H7: u32 = 0x5BE0CD19;

        const K: [u32; 64] = [
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
            0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
            0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
            0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
            0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
            0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
            0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
            0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
            0xC67178F2,
        ];

        pub fn new() -> Self {
            Self(
                Self::H0,
                Self::H1,
                Self::H2,
                Self::H3,
                Self::H4,
                Self::H5,
                Self::H6,
                Self::H7,
            )
        }
    }

    impl Hash for SHA256Hash {
        fn to_vec(&self) -> Vec<u8> {
            let mut v = Vec::new();
            v.append(&mut self.0.to_be_bytes().to_vec());
            v.append(&mut self.1.to_be_bytes().to_vec());
            v.append(&mut self.2.to_be_bytes().to_vec());
            v.append(&mut self.3.to_be_bytes().to_vec());
            v.append(&mut self.4.to_be_bytes().to_vec());
            v.append(&mut self.5.to_be_bytes().to_vec());
            v.append(&mut self.6.to_be_bytes().to_vec());
            v.append(&mut self.7.to_be_bytes().to_vec());
            v
        }

        fn process_chunks(&self, chunk: &[u8]) -> SHA256Hash {
            // Convert 64 byte chunks to 16 32-bit big-endian words
            let mut words: Vec<u32> = chunk
                .chunks(4)
                .map(|x| u32::from_be_bytes(x.try_into().unwrap()))
                .collect();

            // Creates 64 long vec
            for i in 16..64 {
                let s0 = right_rot(words[i - 15], 7)
                    ^ right_rot(words[i - 15], 18)
                    ^ (words[i - 15] >> 3);
                let s1 = right_rot(words[i - 2], 17)
                    ^ right_rot(words[i - 2], 19)
                    ^ (words[i - 2] >> 10);
                words.push(
                    words[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(words[i - 7])
                        .wrapping_add(s1),
                );
            }

            // Init values
            let mut a = self.0;
            let mut b = self.1;
            let mut c = self.2;
            let mut d = self.3;
            let mut e = self.4;
            let mut f = self.5;
            let mut g = self.6;
            let mut h = self.7;

            for i in 0..64 {
                let s1 = right_rot(e, 6) ^ right_rot(e, 11) ^ right_rot(e, 25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA256Hash::K[i])
                    .wrapping_add(words[i]);
                let s0 = right_rot(a, 2) ^ right_rot(a, 13) ^ right_rot(a, 22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            SHA256Hash(a, b, c, d, e, f, g, h)
        }
    }

    impl std::ops::Add for SHA256Hash {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            // Addition that prevents overflows
            Self(
                self.0.wrapping_add(rhs.0),
                self.1.wrapping_add(rhs.1),
                self.2.wrapping_add(rhs.2),
                self.3.wrapping_add(rhs.3),
                self.4.wrapping_add(rhs.4),
                self.5.wrapping_add(rhs.5),
                self.6.wrapping_add(rhs.6),
                self.7.wrapping_add(rhs.7),
            )
        }
    }

    #[derive(Debug)]
    pub struct SHA512Hash(u64, u64, u64, u64, u64, u64, u64, u64);

    impl SHA512Hash {
        const H0: u64 = 0x6A09E667F3BCC908;
        const H1: u64 = 0xBB67AE8584CAA73B;
        const H2: u64 = 0x3C6EF372FE94F82B;
        const H3: u64 = 0xA54FF53A5F1D36F1;
        const H4: u64 = 0x510E527FADE682D1;
        const H5: u64 = 0x9B05688C2B3E6C1F;
        const H6: u64 = 0x1F83D9ABFB41BD6B;
        const H7: u64 = 0x5BE0CD19137E2179;

        const K: [u64; 80] = [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ];

        pub fn new() -> Self {
            Self(
                Self::H0,
                Self::H1,
                Self::H2,
                Self::H3,
                Self::H4,
                Self::H5,
                Self::H6,
                Self::H7,
            )
        }
    }

    impl Hash for SHA512Hash {
        const BLOCK_SIZE: usize = 128;

        fn to_vec(&self) -> Vec<u8> {
            let mut v = Vec::new();
            v.append(&mut self.0.to_be_bytes().to_vec());
            v.append(&mut self.1.to_be_bytes().to_vec());
            v.append(&mut self.2.to_be_bytes().to_vec());
            v.append(&mut self.3.to_be_bytes().to_vec());
            v.append(&mut self.4.to_be_bytes().to_vec());
            v.append(&mut self.5.to_be_bytes().to_vec());
            v.append(&mut self.6.to_be_bytes().to_vec());
            v.append(&mut self.7.to_be_bytes().to_vec());
            v
        }

        fn digest(self, message: &[u8]) -> Vec<u8> {
            // Message length in bits
            let ml: u128 = TryInto::<u128>::try_into(message.len()).unwrap() * 8;
            let mut message = message.to_vec();

            // Pre-processing
            message.push(0x80);

            message = pad_mult(message, 128, 16);
            message.append(&mut u128::to_be_bytes(ml).to_vec());

            // chunk into 1024/8= 128 byte chunks
            let chunks = message.chunks(128);

            let hash = chunks.fold(self, |acc, x| acc.process_chunks(x) + acc);

            hash.to_vec()
        }

        fn process_chunks(&self, chunk: &[u8]) -> SHA512Hash {
            // Convert 64 byte chunks to 16 64-bit big-endian words
            let mut words: Vec<u64> = chunk
                .chunks(8)
                .map(|x| u64::from_be_bytes(x.try_into().unwrap()))
                .collect();

            // Creates 80 long vec
            for i in 16..80 {
                let s0 = right_rot(words[i - 15], 1)
                    ^ right_rot(words[i - 15], 8)
                    ^ (words[i - 15] >> 7);
                let s1 =
                    right_rot(words[i - 2], 19) ^ right_rot(words[i - 2], 61) ^ (words[i - 2] >> 6);
                words.push(
                    words[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(words[i - 7])
                        .wrapping_add(s1),
                );
            }

            // Init values
            let mut a = self.0;
            let mut b = self.1;
            let mut c = self.2;
            let mut d = self.3;
            let mut e = self.4;
            let mut f = self.5;
            let mut g = self.6;
            let mut h = self.7;

            for i in 0..80 {
                let s1 = right_rot(e, 14) ^ right_rot(e, 18) ^ right_rot(e, 41);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA512Hash::K[i])
                    .wrapping_add(words[i]);
                let s0 = right_rot(a, 28) ^ right_rot(a, 34) ^ right_rot(a, 39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            SHA512Hash(a, b, c, d, e, f, g, h)
        }
    }

    impl std::ops::Add for SHA512Hash {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            // Addition that prevents overflows
            Self(
                self.0.wrapping_add(rhs.0),
                self.1.wrapping_add(rhs.1),
                self.2.wrapping_add(rhs.2),
                self.3.wrapping_add(rhs.3),
                self.4.wrapping_add(rhs.4),
                self.5.wrapping_add(rhs.5),
                self.6.wrapping_add(rhs.6),
                self.7.wrapping_add(rhs.7),
            )
        }
    }
}

// Circular left shift
fn left_rot<T>(num: T, by: u8) -> T
where
    T: std::ops::Shl<u8, Output = T>
        + std::ops::Shr<u8, Output = T>
        + std::ops::BitOr<Output = T>
        + Copy
        + Bits,
{
    (num << by) | (num >> (T::BITS - by))
}

// Circular right shift
fn right_rot<T>(num: T, by: u8) -> T
where
    T: std::ops::Shl<u8, Output = T>
        + std::ops::Shr<u8, Output = T>
        + std::ops::BitOr<Output = T>
        + Copy
        + Bits,
{
    (num >> by) | (num << (T::BITS - by))
}

// Pad with 0s to next multiple of mult - sub
fn pad_mult(message: Vec<u8>, mult: usize, sub: usize) -> Vec<u8> {
    let message_len = message.len();

    let size = (((message_len + sub + mult - 1) / mult) * mult) - sub;

    let mut pad = message;
    pad.resize(size, 0);
    pad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lrot0() {
        assert_eq!(
            left_rot(0b00001110_00001110_00001110_00001110_u32, 2),
            0b00111000_00111000_00111000_00111000
        )
    }

    #[test]
    fn lrot1() {
        assert_eq!(
            left_rot(0b10111001_10111001_10111001_10111001_u32, 4),
            0b10011011_10011011_10011011_10011011
        )
    }

    #[test]
    fn rrot0() {
        assert_eq!(
            right_rot(0b00001110_00001110_00001110_00001100_u32, 2),
            0b00000011_10000011_10000011_10000011
        )
    }

    #[test]
    fn rrot1() {
        assert_eq!(
            right_rot(0b10111001_10111001_10111001_10111001_u32, 4),
            0b10011011_10011011_10011011_10011011
        )
    }

    #[test]
    fn rrot_u64() {
        assert_eq!(
            right_rot(
                0b10111001_10111001_10111001_10111001_10111001_10111001_10111001_10111001_u64,
                4
            ),
            0b10011011_10011011_10011011_10011011_10011011_10011011_10011011_10011011
        )
    }

    #[test]
    fn pad() {
        assert_eq!(
            pad_mult(vec![20, 82, 21, 05], 3, 1),
            vec![20, 82, 21, 05, 0]
        )
    }

    #[test]
    fn pad_overflow() {
        assert_eq!(
            pad_mult(vec![20, 82, 21, 05, 22, 40, 34, 15], 3, 2),
            vec![20, 82, 21, 05, 22, 40, 34, 15, 0, 0]
        )
    }

    #[test]
    fn sha1_empty() {
        let key = b"";
        let result = vec![
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(sha1::SHA1Hash::new().digest(key), result)
    }

    #[test]
    fn sha1_single_chunk() {
        let key = b"Primm";
        let result = vec![
            0x59, 0x07, 0x84, 0x5c, 0xeb, 0x72, 0x05, 0x8d, 0xa5, 0x36, 0xa6, 0x23, 0xa0, 0x83,
            0x8c, 0x5c, 0x1b, 0x92, 0x57, 0xe0,
        ];
        assert_eq!(sha1::SHA1Hash::new().digest(key), result)
    }

    #[test]
    fn sha1_mult_chunk() {
        let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";
        let result = vec![
            0xd2, 0x6c, 0xf5, 0xf8, 0x56, 0xae, 0xaa, 0x77, 0xa7, 0xfb, 0xaa, 0x32, 0x6f, 0x7d,
            0x31, 0x2c, 0xba, 0xb5, 0xaa, 0x4b,
        ];
        assert_eq!(sha1::SHA1Hash::new().digest(key), result)
    }

    #[test]
    fn sha256_empty() {
        let key = b"";
        let result = vec![
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha2::SHA256Hash::new().digest(key), result)
    }

    #[test]
    fn sha256_single_chunk() {
        let key = b"Primm";
        let result = vec![
            0xc0, 0xdb, 0x4a, 0xab, 0x55, 0x0b, 0x16, 0xb1, 0xeb, 0x4a, 0xbf, 0x1b, 0xca, 0xf3,
            0xb3, 0x42, 0x65, 0x39, 0xf9, 0x83, 0x8e, 0xd2, 0x1f, 0x70, 0x75, 0x22, 0x3f, 0x90,
            0xbc, 0x3a, 0xd2, 0x2d,
        ];
        assert_eq!(sha2::SHA256Hash::new().digest(key), result)
    }

    #[test]
    fn sha256_mult_chunk() {
        let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";
        let result = vec![
            0x60, 0x24, 0x4f, 0x16, 0x18, 0x27, 0xbb, 0x1f, 0xe6, 0x2a, 0xcc, 0xf0, 0xd4, 0xa5,
            0x42, 0x16, 0xdf, 0x21, 0x03, 0x14, 0x6b, 0x18, 0xe4, 0xce, 0xe6, 0x10, 0xac, 0x97,
            0x24, 0x6c, 0x0b, 0x0b,
        ];
        assert_eq!(sha2::SHA256Hash::new().digest(key), result)
    }

    #[test]
    fn sha512_empty() {
        let key = b"";
        let result = vec![
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(sha2::SHA512Hash::new().digest(key), result)
    }

    #[test]
    fn sha512_single_chunk() {
        let key = b"Primm";
        let result = vec![
            0x6d, 0xfa, 0x6d, 0x53, 0x54, 0x15, 0xd9, 0x70, 0x46, 0xa8, 0xa6, 0x8f, 0xe2, 0x5c,
            0x00, 0x74, 0xea, 0xba, 0xe5, 0x0c, 0xfe, 0x52, 0x10, 0x9c, 0xd1, 0x77, 0x8e, 0x3e,
            0xc6, 0x34, 0xee, 0xad, 0x00, 0xaf, 0x44, 0x1d, 0x0c, 0x49, 0x13, 0xfa, 0x2a, 0xc0,
            0x6e, 0xd7, 0xe9, 0x73, 0x5a, 0x84, 0x00, 0x53, 0xb2, 0x9e, 0x72, 0x60, 0xb6, 0x32,
            0x8f, 0xd4, 0x89, 0x31, 0xa2, 0x74, 0x39, 0xba,
        ];
        assert_eq!(sha2::SHA512Hash::new().digest(key), result)
    }
}
