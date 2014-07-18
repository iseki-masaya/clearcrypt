pub type PubKey = [u8, ..32];

pub struct PrivKey([u8, ..32]);

impl PrivKey {
    pub fn new(k: &[u8, ..32]) -> PrivKey {
        let mut k = *k;
        k[0]  &= 0b_1111_1000;
        k[31] &= 0b_0111_1111;
        k[31] |= 0b_0100_0000;

        return PrivKey(k);
    }
}

type MultInt = [u64, ..20];

static MINT_ZERO: MultInt = [
    0,0,0,0,0,
    0,0,0,0,0,
    0,0,0,0,0,
    0,0,0,0,0
];

pub struct Int25519 {
    pub v: [u64, ..10],
}

pub static EIGHT_TIMES_PRIME: Int25519 = Int25519 {
    v: [
        // 152 is 19 << 3
        (8<<26) - 152 as u64,
        (8<<25) -   8 as u64,
        (8<<26) -   8 as u64,
        (8<<25) -   8 as u64,
        (8<<26) -   8 as u64,
        (8<<25) -   8 as u64,
        (8<<26) -   8 as u64,
        (8<<25) -   8 as u64,
        (8<<26) -   8 as u64,
        (8<<25) -   8 as u64,
    ]
};

pub static INT25519_ZERO: Int25519 = Int25519 {
    v: [
        0,0,0,0,0,
        0,0,0,0,0
    ]
};

pub static INT25519_ONE: Int25519 = Int25519 {
    v: [
        1,0,0,0,0,
        0,0,0,0,0
    ]
};


impl Clone for Int25519 {
    fn clone(&self) -> Int25519 {
        Int25519 { v: self.v }
    }
}

impl Int25519 {
    pub fn from_key(k: &PubKey) -> Int25519 {
        // Even idex such as a[0],a[2] takes 26 bit;
        // Odd idex such as a[1],a[3] takes 25 bit;
        return Int25519 {
            v: [
                (k[0]  as u64 >>  0) | (k[1] as u64 << 8) |
                (k[2]  as u64 << 16) | ((k[3] as u64 & 0b11) << 24),

                (k[3]  as u64 >>  2) | (k[4] as u64 << 6) |
                (k[5]  as u64 << 14) | ((k[6] as u64 & 0b111) << 22),

                (k[6]  as u64 >>  3) | (k[7] as u64 << 5) |
                (k[8]  as u64 << 13) | ((k[9] as u64 & 0b11111) << 21),

                (k[9]  as u64 >>  5) | (k[10] as u64 << 3) |
                (k[11] as u64 << 11) | ((k[12] as u64 & 0b111111) << 19),

                (k[12] as u64 >>  6) | (k[13] as u64 << 2) |
                (k[14] as u64 << 10) | (k[15] as u64 << 18),

                (k[16] as u64 >>  0) | (k[17] as u64 << 8) |
                (k[18] as u64 << 16) | ((k[19] as u64 & 0b1) << 24),

                (k[19] as u64 >>  1) | (k[20] as u64 << 7) |
                (k[21] as u64 << 15) | ((k[22] as u64 & 0b111) << 23),

                (k[22] as u64 >>  3) | (k[23] as u64 << 5) |
                (k[24] as u64 << 13) | ((k[25] as u64 & 0b1111) << 21),

                (k[25] as u64 >>  4) | (k[26] as u64 << 4) |
                (k[27] as u64 << 12) | ((k[28] as u64 & 0b111111) << 20),

                (k[28] as u64 >>  6) | (k[29] as u64 << 2) |
                (k[30] as u64 << 10) | ((k[31] as u64 & 0b1111111) << 18),
            ]
        };
    }

    pub fn to_key(&self) -> PubKey {
        let mut a = self.clone();
        a.contract();
        let v = a.v;

        return [
            ((v[0] >> 0) & 0xFF) as u8,
            ((v[0] >> 8) & 0xFF) as u8,
            ((v[0] >> 16) & 0xFF) as u8,
            ((v[0] >> 24) | ((v[1] & 0b111111) << 2)) as u8,
            ((v[1] >> 6) & 0xFF) as u8,
            ((v[1] >> 14) & 0xFF) as u8,
            ((v[1] >> 22) | ((v[2] & 0b11111) << 3)) as u8,
            ((v[2] >> 5) & 0xFF) as u8,
            ((v[2] >> 13) & 0xFF) as u8,
            ((v[2] >> 21) | ((v[3] & 0b111) << 5)) as u8,
            ((v[3] >> 3) & 0xFF) as u8,
            ((v[3] >> 11) & 0xFF) as u8,
            ((v[3] >> 19) | ((v[4] & 0b11) << 6)) as u8,
            ((v[4] >> 2) & 0xFF) as u8,
            ((v[4] >> 10) & 0xFF) as u8,
            ((v[4] >> 18) & 0xFF) as u8,
            ((v[5] >> 0) & 0xFF) as u8,
            ((v[5] >> 8) & 0xFF) as u8,
            ((v[5] >> 16) & 0xFF) as u8,
            ((v[5] >> 24) | ((v[6] & 0b1111111) << 1)) as u8,
            ((v[6] >> 7) & 0xFF) as u8,
            ((v[6] >> 15) & 0xFF) as u8,
            ((v[6] >> 23) | ((v[7] & 0b11111) << 3)) as u8,
            ((v[7] >> 5) & 0xFF) as u8,
            ((v[7] >> 13) & 0xFF) as u8,
            ((v[7] >> 21) | ((v[8] & 0b1111) << 4)) as u8,
            ((v[8] >> 4) & 0xFF) as u8,
            ((v[8] >> 12) & 0xFF) as u8,
            ((v[8] >> 20) | ((v[9] & 0b11) << 6)) as u8,
            ((v[9] >> 2) & 0xFF) as u8,
            ((v[9] >> 10) & 0xFF) as u8,
            ((v[9] >> 18)) as u8, // a[9] is 25-bit, so msb is always 0
        ];
    }

    fn _add(&mut self, b: &Int25519) {
        for idx in range(0u, 10) {
            self.v[idx] += b.v[idx];
        }
    }

    pub fn add(&self, b: &Int25519) -> Int25519 {
        let mut c = self.clone();
        c._add(b);
        c.contract();
        return c;
    }

    fn _sub(&mut self, b: &Int25519) {
        self._add(&EIGHT_TIMES_PRIME);
        for idx in range(0u, 10) {
            self.v[idx] -= b.v[idx];
        }
    }

    pub fn sub(&self, b: &Int25519) -> Int25519 {
        let mut c = self.clone();
        c._sub(b);
        c.contract();
        return c;
    }

    fn _mul(&mut self, y: &Int25519) -> Int25519 {
        let a = &self.v.clone();
        let b = &y.v;

        let mut res: MultInt = MINT_ZERO;
        for i in range(0u, 10) {
            for j in range(0u, 10) {
                let idx = i + j;
                // if idx is even and i is odd, j is odd.
                let coefficient = if idx&1==0 && i&1==1 {2u64} else {1u64};
                let c = a[i] * b[j] * coefficient;
                res[idx] += c;
            }
        }
        return Int25519::from_mult_int(&res);
    }

    pub fn mul(&self, y: &Int25519) -> Int25519 {
        let mut c = self.clone();
        c = c._mul(y);
        c.contract();
        return c;
    }

    pub fn mul_scalar(&self, b: u64) -> Int25519 {
        let mut c = self.clone();
        for idx in range(0u, 10) {
            c.v[idx] *= b;
        }
        c.contract();
        return c;
    }

    pub fn contract(&mut self) {
        self.reduce();
        self.v[0] += (self.v[9] >> 25)*19;
        self.v[9]  = self.v[9] & ((1<<25) - 1);
        self.reduce();
        self.v[0] += (self.v[9] >> 25)*19;
        self.v[9]  = self.v[9] & ((1<<25) - 1);

        self.v[0] += 19;

        self.reduce();
        self.v[0] += (self.v[9] >> 25)*19;
        self.v[9]  = self.v[9] & ((1<<25) - 1);

        self.v[0] += (1<<26) - 19;
        self.v[1] += (1<<25) - 1;
        self.v[2] += (1<<26) - 1;
        self.v[3] += (1<<25) - 1;
        self.v[4] += (1<<26) - 1;
        self.v[5] += (1<<25) - 1;
        self.v[6] += (1<<26) - 1;
        self.v[7] += (1<<25) - 1;
        self.v[8] += (1<<26) - 1;
        self.v[9] += (1<<25) - 1;

        self.reduce();
        self.v[9]  = self.v[9] & ((1<<25) - 1);
    }

    pub fn inverse(&self) -> Int25519 {
        // compute x^(2^n)
        fn square_n(a: &Int25519, n: uint) -> Int25519 {
            let mut y = a.clone();
            for _ in range(0, n) {
                y = y.mul(&y);
            }
            return y;
        }

        let x2 = self.mul(self);
        let x4 = x2.mul(&x2);
        let x8 = x4.mul(&x4);
        let x9 = x8.mul(self);
        let x11 = x9.mul(&x2);
        let x22 = x11.mul(&x11);

        let y5_0        = x22.mul(&x9);              //x^(2^5   - 2^0  )
        let y10_5       = square_n(&y5_0, 5);        //x^(2^10  - 2^5  )
        let y10_0       = y10_5.mul(&y5_0);         //x^(2^10  - 2^0  )
        let y20_10      = square_n(&y10_0, 10);      //x^(2^20  - 2^10 )
        let y20_0       = y20_10.mul(&y10_0);        //x^(2^20  - 2^0  )
        let y40_20      = square_n(&y20_0, 20);      //x^(2^40  - 2^20 )
        let y40_0       = y40_20.mul(&y20_0);        //x^(2^40  - 2^0  )
        let y50_10      = square_n(&y40_0, 10);      //x^(2^50  - 2^10 )
        let y50_0       = y50_10.mul(&y10_0);        //x^(2^50  - 2^0  )
        let y100_50     = square_n(&y50_0, 50);      //x^(2^100 - 2^50 )
        let y100_0      = y100_50.mul(&y50_0);       //x^(2^100 - 2^0  )
        let y200_100    = square_n(&y100_0, 100);    //x^(2^200 - 2^100)
        let y200_0      = y200_100.mul(&y100_0);     //x^(2^200 - 2^0  )
        let y250_50     = square_n(&y200_0, 50);     //x^(2^250 - 2^50 )
        let y250_0      = y250_50.mul(&y50_0);       //x^(2^250 - 2^0  )
        let y255_5      = square_n(&y250_0, 5);      //x^(2^255 - 2^5  )
        let z255_21     = y255_5.mul(&x11);          //x^(2^255 - 21   )

        return z255_21;
    }

    pub fn swap(flag: u64, a: &Int25519, b: &Int25519) -> (Int25519, Int25519) {
        let mut c = a.clone();
        let mut d = b.clone();
        for idx in range(0u, 10) {
            let x = flag * (c.v[idx]^d.v[idx]);
            c.v[idx] ^= x;
            d.v[idx] ^= x;
        }
        return (c, d);
    }

    fn from_mult_int(a: &MultInt) -> Int25519 {
        let mut b: Int25519 = INT25519_ZERO;
        for idx in range(0u, 10) {
            b.v[idx] = a[idx] + a[idx+10]*19;
        }
        return b;
    }

    // this method don't reduce last element.
    fn reduce(&mut self) {
        for idx in range(0u, 9) {
            let shift = if idx&1 == 0 {26u} else {25u};
            self.v[idx+1] += self.v[idx] >> shift;
            self.v[idx]    = self.v[idx] & ((1<<shift) - 1);
        }
    }
}

pub struct Point {
    x: Int25519,
    z: Int25519
}

static POINT_ZERO: Point = Point { x: INT25519_ONE , z: INT25519_ZERO};

impl Point {
    pub fn double_add(q: &Point, r: &Point, x1: &Int25519) -> (Point, Point) {
        //(qx + qz)
        let q_add = q.x.add(&q.z);
        //(qx + qz)^2
        let q_add_2 = q_add.mul(&q_add);
        //(qx - qz)
        let q_sub = q.x.sub(&q.z);
        //(qx - qz)^2
        let q_sub_2 = q_sub.mul(&q_sub);
        // x2 = (qx + qz)^2 * (qx - qz)^2
        let x2 = q_add_2.mul(&q_sub_2);
        let z2 = {
            let a = 486662;
            // (qx + qz)^2 - (qx - qz)^2
            let ql = q_add_2.sub(&q_sub_2);
            // ( (qx + qz)^2 + (A - 2)/4 * qql )
            let qr = q_add_2.add( &ql.mul_scalar( (a - 2) / 4) );

            ql.mul(&qr)
        };

        //(rx + rz)
        let r_add = r.x.add(&r.z);
        //(rx - rz)
        let r_sub = r.x.sub(&r.z);
        //(qx - qz)*(rx + rz)
        let t1 = q_sub.mul(&r_add);
        //(qx + qz)*(rx - rz)
        let t2 = q_add.mul(&r_sub);

        //(qx - qz)*(rx + rz) + (qx + qz)*(rx - rz)
        let t_add = t1.add(&t2);
        //(qx - qz)*(rx + rz) - (qx + qz)*(rx - rz)
        let t_sub = t1.sub(&t2);
        //z1 is always 1
        let x3 = t_add.mul(&t_add);
        let z3 = t_sub.mul(&t_sub).mul(x1);

        let q_add_q = Point { x:x2, z:z2};
        let q_add_r = Point { x:x3, z:z3};
        return (q_add_q, q_add_r);
    }

    pub fn swap(flag: u64, a: &Point, b: &Point) -> (Point, Point) {
        let (ax, bx) = Int25519::swap(flag, &a.x, &b.x);
        let (az, bz) = Int25519::swap(flag, &a.z, &b.z);
        return (Point {x:ax, z:az}, Point {x:bx, z:bz} );
    }

    pub fn to_int25519(&self) -> Int25519 {
        return self.x.mul(&self.z.inverse());
    }
}

pub fn curve25519(n: &PrivKey, q: &PubKey) -> PubKey {
    let PrivKey(n) = *n;

    let q = Int25519::from_key(q);

    let mut kq  = POINT_ZERO;
    let mut k1q = Point { x: q, z: INT25519_ONE};

    for i in range(0u, 32*8 - 1).rev() {
        let b = ( (n[i / 8]>>(i%8)) & 0x01 ) as u64;
        let (c, c1) = Point::swap(b, &kq, &k1q);
        let (d, d1) = Point::double_add(&c, &c1, &q);
        let (e, e1) = Point::swap(b, &d, &d1);

        kq = e;
        k1q = e1;
    }

    let kq = kq.to_int25519();
    return kq.to_key();
}

#[cfg(test)]
mod test {
    use crypt::curve25519::{Int25519, curve25519, PrivKey, Point, INT25519_ONE, POINT_ZERO};
    use num::bigint::{BigInt, ToBigInt};
    use num::Integer;
    use std::num::FromStrRadix;

    // 2^(255-19)
    static bits: &'static str = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111101101";
    static ZERO: Int25519 = Int25519 { v:[0,0,0,0,0,0,0,0,0,0]};
    static ONE: Int25519 = Int25519 { v:[1,0,0,0,0,0,0,0,0,0]};

    static test_case: &'static [Int25519] = &[
        ZERO,
        ONE,
        Int25519{ v:[3,0,0,0,0,0,0,0,0,0] },
        Int25519{ v:[5,0,0,0,0,0,0,0,0,0] },
        Int25519{ v:[2,5,5,1,9,2,5,5,1,9] },
        Int25519{ v:[4,1,4,1,7,4,1,4,1,7] },
        Int25519{ v:[(1<<23),..10] },
        Int25519{ v:[(1<<24),..10] },
        Int25519{ v:[(1<<25),..10] },
        Int25519{ v:[(1<<26),..10] },
        Int25519{ v:[(1<<27),..10] },
    ];

    impl ToBigInt for Int25519 {
        fn to_bigint(&self) -> Option<BigInt> {
            let mut res = (0u).to_bigint().unwrap();
            res = res.add( &(self.v[0].to_bigint().unwrap().shl(&0u)  ) );
            res = res.add( &(self.v[1].to_bigint().unwrap().shl(&26u) ) );
            res = res.add( &(self.v[2].to_bigint().unwrap().shl(&51u) ) );
            res = res.add( &(self.v[3].to_bigint().unwrap().shl(&77u) ) );
            res = res.add( &(self.v[4].to_bigint().unwrap().shl(&102u)) );
            res = res.add( &(self.v[5].to_bigint().unwrap().shl(&128u)) );
            res = res.add( &(self.v[6].to_bigint().unwrap().shl(&153u)) );
            res = res.add( &(self.v[7].to_bigint().unwrap().shl(&179u)) );
            res = res.add( &(self.v[8].to_bigint().unwrap().shl(&204u)) );
            res = res.add( &(self.v[9].to_bigint().unwrap().shl(&230u)) );
            return Some(res);
        }
    }

    impl PartialEq for Int25519 {
        fn eq(&self, b: &Int25519) -> bool {
            let self_key = self.to_key();
            let b_key = b.to_key();
            return self_key.as_slice() == b_key.as_slice();
        }
    }

    impl ::std::fmt::Show for Int25519 {
        fn fmt(&self, a: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            return self.to_key().as_slice().fmt(a);
        }
    }

    #[test]
    fn test_int25519_to_bigint() {
        let v: Int25519 = Int25519 {
            v: [
                (1<<26) - 19 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
            ]
        };
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);
        assert_eq!(p.unwrap(), v.to_bigint().unwrap());
    }

    #[test]
    fn test_int25519_add() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        for a in test_case.iter() {
            for b in test_case.iter() {
                let abig = a.to_bigint().unwrap();
                let bbig = b.to_bigint().unwrap();
                let mut ans = abig.add(&bbig);
                ans = ans.mod_floor(&p.clone().unwrap());

                let c = a.add(b);
                assert_eq!(c.to_bigint().unwrap(), ans.to_bigint().unwrap());
            }
        }
    }

    #[test]
    fn test_int25519_sub() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        for a in test_case.iter() {
            for b in test_case.iter() {
                let abig = a.to_bigint().unwrap();
                let bbig = b.to_bigint().unwrap();
                let mut ans = abig.sub(&bbig);
                ans = ans.mod_floor(&p.clone().unwrap());

                let c = a.sub(b);
                assert_eq!(c.to_bigint().unwrap(), ans.to_bigint().unwrap());
            }
        }
    }

    #[test]
    fn test_int25519_mul() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        for a in test_case.iter() {
            for b in test_case.iter() {
                let abig = a.to_bigint().unwrap();
                let bbig = b.to_bigint().unwrap();
                let mut ans = abig.mul(&bbig);
                ans = ans.mod_floor(&p.clone().unwrap());

                let c = a.mul(b);
                assert_eq!(c.to_bigint().unwrap(), ans.to_bigint().unwrap());
            }
        }
    }

    #[test]
    fn test_int25519_mul_associative() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        //associative property: (a * b) * c = a * (b * c)
        for a in test_case.iter() {
            for b in test_case.iter() {
                for c in test_case.iter() {
                    let abig = a.to_bigint().unwrap();
                    let bbig = b.to_bigint().unwrap();
                    let cbig = c.to_bigint().unwrap();
                    let mut ans = abig.mul(&bbig).mul(&cbig);
                    ans = ans.mod_floor(&p.clone().unwrap());

                    // (a * b) * c
                    let t1 = a.mul(b);
                    let lh = t1.mul(c);
                    // a * (b * c)
                    let t2 = b.mul(c);
                    let rh = a.mul(&t2);

                    assert_eq!(lh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                    assert_eq!(rh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                }
            }
        }
    }

    #[test]
    fn test_int25519_add_associative() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        //associative property: (a + b) + c = a + (b + c)
        for a in test_case.iter() {
            for b in test_case.iter() {
                for c in test_case.iter() {
                    let abig = a.to_bigint().unwrap();
                    let bbig = b.to_bigint().unwrap();
                    let cbig = c.to_bigint().unwrap();
                    let mut ans = abig.add(&bbig).add(&cbig);
                    ans = ans.mod_floor(&p.clone().unwrap());

                    // (a + b) + c
                    let t1 = a.add(b);
                    let lh = t1.add(c);
                    // a + (b + c)
                    let t2 = b.add(c);
                    let rh = a.add(&t2);

                    assert_eq!(lh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                    assert_eq!(rh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                }
            }
        }
    }

    #[test]
    fn test_int25519_sub_associative() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        //associative property: (a - b) - c = a - (b + c)
        for a in test_case.iter() {
            for b in test_case.iter() {
                for c in test_case.iter() {
                    let abig = a.to_bigint().unwrap();
                    let bbig = b.to_bigint().unwrap();
                    let cbig = c.to_bigint().unwrap();
                    let mut ans = abig.sub(&bbig).sub(&cbig);
                    ans = ans.mod_floor(&p.clone().unwrap());

                    // (a - b) - c
                    let t1 = a.sub(b);
                    let lh = t1.sub(c);
                    // a - (b + c)
                    let t2 = b.add(c);
                    let rh = a.sub(&t2);

                    assert_eq!(lh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                    assert_eq!(rh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                }
            }
        }
    }

    #[test]
    fn test_int25519_add_mul_distributive() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        //distributive property: a * (b + c) = a*b + a*c
        for a in test_case.iter() {
            for b in test_case.iter() {
                for c in test_case.iter() {
                    let abig = a.to_bigint().unwrap();
                    let bbig = b.to_bigint().unwrap();
                    let cbig = c.to_bigint().unwrap();
                    let mut ans = bbig.add(&cbig).mul(&abig);
                    ans = ans.mod_floor(&p.clone().unwrap());

                    // a * (b + c)
                    let t1 = b.add(c);
                    let lh = a.mul(&t1);
                    // a*b + a*c
                    let t2 = a.mul(b);
                    let t3 = a.mul(c);
                    let rh = t2.add(&t3);

                    assert_eq!(lh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                    assert_eq!(rh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                }
            }
        }
    }

    #[test]
    fn test_int25519_sub_mul_distributive() {
        let p: Option<BigInt> = FromStrRadix::from_str_radix(bits, 2);

        //distributive property: a * (b - c) = a*b - a*c
        for a in test_case.iter() {
            for b in test_case.iter() {
                for c in test_case.iter() {
                    let abig = a.to_bigint().unwrap();
                    let bbig = b.to_bigint().unwrap();
                    let cbig = c.to_bigint().unwrap();
                    let mut ans = bbig.sub(&cbig).mul(&abig);
                    ans = ans.mod_floor(&p.clone().unwrap());

                    // a * (b - c)
                    let t1 = b.sub(c);
                    let lh = a.mul(&t1);
                    // a*b - a*c
                    let t2 = a.mul(b);
                    let t3 = a.mul(c);
                    let rh = t2.sub(&t3);

                    assert_eq!(lh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                    assert_eq!(rh.to_bigint().unwrap(), ans.to_bigint().unwrap());
                }
            }
        }
    }

    #[test]
    fn test_int25519_inverse() {
        for a in test_case.iter() {
            if a.to_bigint().unwrap() == ZERO.to_bigint().unwrap() {
                continue;
            }
            let b = a.inverse();
            let c = a.mul(&b);
            assert_eq!(c.to_bigint().unwrap(), ONE.to_bigint().unwrap());
        }
    }

    #[test]
    fn test_int25519_swap() {
        for aa in test_case.iter() {
            for bb in test_case.iter() {
                let mut a = aa.clone();
                let mut b = bb.clone();
                a.contract();
                b.contract();

                let (c, d) = Int25519::swap(1u64, &a, &b);
                assert_eq!(c.to_bigint().unwrap(), b.to_bigint().unwrap());
                assert_eq!(d.to_bigint().unwrap(), a.to_bigint().unwrap());

                let (e, f) = Int25519::swap(0u64, &a, &b);
                assert_eq!(e.to_bigint().unwrap(), a.to_bigint().unwrap());
                assert_eq!(f.to_bigint().unwrap(), b.to_bigint().unwrap());
            }
        }
    }

    #[test]
    fn test_int25519_contract_two255() {
        // 2^255
        let mut a : Int25519 = Int25519 {
            v : [0,0,0,0,0,0,0,0,0,(1<<25)]
        };
        let ans : Int25519 = Int25519 {
            v : [19,0,0,0,0,0,0,0,0,0]
        };
        a.contract();
        assert_eq!(a.to_bigint().unwrap(), ans.to_bigint().unwrap());
    }

    #[test]
    fn test_int25519_contract_two255_twice() {
        // 2^255
        let mut a : Int25519 = Int25519 {
            v : [0,0,0,0,0,0,0,0,0,2*(1<<25)]
        };
        let ans : Int25519 = Int25519 {
            v : [2*19,0,0,0,0,0,0,0,0,0]
        };
        a.contract();
        assert_eq!(a.to_bigint().unwrap(), ans.to_bigint().unwrap());
    }

    #[test]
    fn test_int25519_contract_two255mx_lt19() {
        // 2^255-19
        let a: Int25519 = Int25519 {
            v: [
                (1<<26) - 19 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
                (1<<26) -  1 as u64,
                (1<<25) -  1 as u64,
            ]
        };
        let zero : Int25519 = Int25519 {
            v : [0,0,0,0,0,0,0,0,0,0]
        };
        for i in range(0u64, 20) {
            let mut b = a.clone();
            let mut ans = zero.clone();
            // 2^255-19+i
            b.v[0] += i;
            ans.v[0] += i;
            b.contract();
            assert_eq!(b.to_bigint().unwrap(), ans.to_bigint().unwrap());
        }
    }

    #[test]
    fn test_curve25519_double_add() {
        for i in test_case.iter() {

            let one = Point { x: *i, z: INT25519_ONE };
            let zero = POINT_ZERO;
            // (2 * i_one, i_one)
            let (two, one_2) = Point::double_add(&one, &zero, i);

            assert_eq!(*i, one_2.to_int25519());
            // Q', Q, Q-Q' instead of Q, Q', Q-Q'
            let (_, one_3) = Point::double_add(&zero, &one, i);
            assert_eq!(*i, one_3.to_int25519());

            let (four, three) = Point::double_add(&two, &one, i);
            let (six, five) = Point::double_add(&three, &two, i);
            let (eight, seven) = Point::double_add(&four, &three, i);

            // three == two + one, three_2 == one + two
            let (two_2, three_2) = Point::double_add(&one, &two, i);
            assert_eq!(two.to_int25519(), two_2.to_int25519());
            assert_eq!(three.to_int25519(), three_2.to_int25519());

            // six == three * 2, six_2 == four + two
            let (eight_2, six_2) = Point::double_add(&four, &two, &two.to_int25519());
            assert_eq!(six.to_int25519(), six_2.to_int25519());
            assert_eq!(eight.to_int25519(), eight_2.to_int25519());

            // seven == four + three, seven_2 == two + five (Q - Q' != i)
            let (_, seven_2) = Point::double_add(&two, &five, &three.to_int25519());
            assert_eq!(seven.to_int25519(), seven_2.to_int25519());

            // eight == four * 2, eight_2 == three + five (Q - Q' != i)
            let (_, eight_2) = Point::double_add(&three, &five, &two.to_int25519());
            assert_eq!(eight.to_int25519(), eight_2.to_int25519());
        }
    }

    #[test]
    fn test_curve25519() {
        for i in test_case.iter() {
            let basepoint = i.to_key();
            for n in test_case.iter() {
                let n = n.to_key();
                let n = PrivKey::new(&n);
                for m in test_case.iter() {
                    let m = m.to_key();
                    let m = PrivKey::new(&m);

                    let nP = curve25519(&n, &basepoint);
                    let mnP = curve25519(&m, &nP);

                    let mP = curve25519(&m, &basepoint);
                    let nmP = curve25519(&n, &mP);

                    assert_eq!(nmP.as_slice(), mnP.as_slice());
                }
            }
        }
    }
}