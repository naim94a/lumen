use super::Error;
use serde::{ser, ser::Impossible, Serialize};
use std::io::Write;

struct Serializer<W: Write> {
    output: W,
}

pub fn to_writer<T: Serialize, W: Write>(v: &T, w: W) -> Result<(), Error> {
    let mut serializer = Serializer { output: w };
    v.serialize(&mut serializer)?;
    Ok(())
}

#[allow(dead_code)]
pub fn to_vec<T: Serialize>(v: &T) -> Result<Vec<u8>, Error> {
    let mut buf = vec![];
    to_writer(v, &mut buf)?;
    Ok(buf)
}

impl<W: Write> Serializer<W> {
    fn pack_dd(&mut self, num: u32) -> Result<(), Error> {
        let mut buf = [0u8; 5];
        let bytes = super::packing::pack_dd(num, &mut buf);
        self.output.write_all(&buf[..bytes])?;
        Ok(())
    }

    fn pack_str(&mut self, s: &str) -> Result<(), Error> {
        self.output.write_all(s.as_bytes())?;
        self.output.write_all(&[0])?;
        Ok(())
    }

    fn pack_bytes(&mut self, b: &[u8]) -> Result<(), Error> {
        self.pack_dd(b.len() as u32)?;
        self.output.write_all(b)?;
        Ok(())
    }
}

impl<'a, W: Write> ser::Serializer for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Impossible<(), Self::Error>;
    type SerializeTupleVariant = Impossible<(), Self::Error>;
    type SerializeMap = Impossible<(), Self::Error>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Impossible<(), Self::Error>;

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.output.write_all(&[v])?;
        Ok(())
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.pack_dd(v)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        let high = (v >> 32) & 0xffffffff;
        let low = v & 0xffffffff;
        self.pack_dd(high as u32)?;
        self.pack_dd(low as u32)?;
        Ok(())
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.pack_str(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.pack_bytes(v)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        // unit contains no information...
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_unit_variant(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self, _name: &'static str, _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str, _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let len = len.unwrap();
        self.pack_dd(len as u32)?;
        Ok(self)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self, _name: &'static str, _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        unreachable!();
    }

    fn serialize_tuple_variant(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str, _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        unreachable!()
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        unreachable!()
    }

    fn serialize_struct(
        self, _name: &'static str, _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        // structs will simply be flattened
        Ok(self)
    }

    fn serialize_struct_variant(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str, _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        unreachable!()
    }
}

impl<'a, W: Write> ser::SerializeSeq for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, W: Write> ser::SerializeTuple for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, W: Write> ser::SerializeStruct for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self, _key: &'static str, value: &T,
    ) -> Result<(), Self::Error> {
        // struct names have no meaning
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ser_hello() {
        #[derive(serde::Serialize)]
        struct Test<'a> {
            arr: [u8; 16],
            s: &'a str,
            b: &'a [u8],
            i: u32,
            q: u64,
        }
        let v = Test {
            arr: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            s: "somestring",
            b: b"bytes",
            i: 0x20,
            q: 0x20,
        };
        let v = super::to_vec(&v).expect("failed to serialize dummy");
        assert_eq!(v, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10somestring\x00\x05bytes\x20\x00\x20");
    }
}
