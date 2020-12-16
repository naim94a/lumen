/// packs a dd into `buf` returning amout of bytes written.
/// Returns 0 if buffer is too small
pub fn pack_dd(v: u32, buf: &mut [u8]) -> usize {
    let bytes = v.to_le_bytes();
    match v {
        0..=0x7f => { // 0..0XXXXXXX (7 bits)
            if buf.len() < 1 {
                return 0;
            }
            buf[0] = bytes[0];
            1
        },
        0x80..=0x3fff => { // 10AAAAAA..BBBBBBBB (14 bits)
            if buf.len() < 2 {
                return 0;
            }
            buf[0] = 0x80 | bytes[1];
            buf[1] = bytes[0];
            2
        },
        0x4000..=0x1fffff => { // 11000000_AAAAAAAA_BBBBBBBB_CCCCCCCC (24 bits)
            if buf.len() < 3 {
                return 0;
            }
            buf[0] = 0xc0;
            buf[1] = bytes[2];
            buf[2] = bytes[1];
            buf[3] = bytes[0];
            4
        },
        0x200000..=u32::MAX => { // 11111111_AAAAAAAA_BBBBBBBB_CCCCCCCC_DDDDDDDD (32 bits)
            if buf.len() < 5 {
                return 0;
            }
            buf[0] = 0xff;
            buf[1] = bytes[3];
            buf[2] = bytes[2];
            buf[3] = bytes[1];
            buf[4] = bytes[0];
            5
        }
    }
}

/// unpacks a dd from `buf`, returning the amount (value, byte consumed)
pub fn unpack_dd(buf: &[u8]) -> (u32, usize) {
    if buf.len() < 1 {
        return (0, 0);
    }

    let msb = buf[0];
    let mut val = [0u8; 4];

    if msb & 0x80 == 0 { // 0......
        val[0] = msb;
        return (u32::from_le_bytes(val), 1);
    }
    if msb & 0x40 == 0 { // 10....../0x80
        if buf.len() < 2 {
            return (0, 0);
        }
        val[1] = msb & 0x3f;
        val[0] = buf[1];
        return (u32::from_le_bytes(val), 2);
    }
    if msb & 0x20 == 0 { // 110...../0xC0
        if buf.len() < 4 {
            return (0, 0);
        }
        val[3] = msb & 0x1f;
        val[2] = buf[1];
        val[1] = buf[2];
        val[0] = buf[3];
        return (u32::from_le_bytes(val), 4);
    }

    if buf.len() < 5 {
        return (0, 0);
    }

    val[3] = buf[1];
    val[2] = buf[2];
    val[1] = buf[3];
    val[0] = buf[4];

    return (u32::from_le_bytes(val), 5);
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "this is a very time consuming test, it should be run in release/profiling mode"]
    fn pack_all_nums() {
        for num in 0..=u32::MAX {
            let mut buf = [0u8; 5];
            let rlen = super::pack_dd(num, &mut buf);
            assert!(rlen > 0);

            let unpacked = super::unpack_dd(&buf[..rlen]);
            assert_eq!(unpacked.1, rlen, "bad unpack size");
            assert_eq!(unpacked.0, num, "values don't match");
        }
    }
}
