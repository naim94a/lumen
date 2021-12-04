use serde::Deserialize;
use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use super::Error;

struct Deserializer<'de> {
    input: &'de [u8],
}

impl<'de> Deserializer<'de> {
    fn from_bytes(b: &'de [u8]) -> Self {
        Self {
            input: b,
        }
    }
    
    fn unpack_dd(&mut self) -> Result<u32, Error> {
        let (v, len) = super::packing::unpack_dd(self.input);
        if len == 0 {
            Err(Error::UnexpectedEof)
        } else {
            self.input = &self.input[len..];
            Ok(v)
        }
    }

    fn unpack_dq(&mut self) -> Result<u64, Error> {
        let a = self.unpack_dd()? as u64;
        let b = self.unpack_dd()? as u64;
        Ok((a << 32) | b)
    }
    
    fn unpack_var_bytes(&mut self) -> Result<&'de [u8], Error> {
        let bytes = self.unpack_dd()? as usize;
        if bytes > self.input.len() {
            return Err(Error::UnexpectedEof);
        }

        let payload = &self.input[..bytes];
        self.input = &self.input[bytes..];
        assert_eq!(payload.len(), bytes);

        Ok(payload)
    }
    
    fn unpack_cstr(&mut self) -> Result<&'de str, Error> {
        let len = self.input.iter().enumerate().find_map(|(idx, &v)| if v == 0 { Some(idx) } else { None });
        let len = match len {
            Some(v) => v,
            None => return Err(Error::UnexpectedEof),
        };
        let res = match std::str::from_utf8(&self.input[..len]) {
            Ok(v) => v,
            Err(err) => {
                return Err(err.into());
            }
        };
        self.input = &self.input[len + 1..];
        Ok(res)
    }

    fn take_byte(&mut self) -> Result<u8, Error> {
        if self.input.is_empty() {
            return Err(Error::UnexpectedEof);
        }

        let v = self.input[0];
        self.input = &self.input[1..];
        Ok(v)
    }
}

/// Returns: a tuple containing the deserialized struct and the bytes used
pub fn from_slice<'a, T: Deserialize<'a>>(b: &'a [u8]) -> Result<(T, usize), Error> {
    let mut de = Deserializer::from_bytes(b);
    let v = T::deserialize(&mut de)?;
    Ok((v, b.len() - de.input.len()))
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u8(self.take_byte()?)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u32(self.unpack_dd()?)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u64(self.unpack_dq()?)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let len = self.unpack_dd()?;
        
        visitor.visit_seq(Access {
            len: len as usize,
            de: &mut *self,
        })
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_borrowed_str(self.unpack_cstr()?)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let v = self.unpack_var_bytes()?;
        visitor.visit_borrowed_bytes(v)
    }
    
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_seq(Access {
            len,
            de: &mut *self,
        })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(self, _name: &'static str, len: usize, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(self, name: &'static str, fields: &'static [&'static str], visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_tuple_struct(name, fields.len(), visitor)
    }

    serde::forward_to_deserialize_any! {
        i8 i16 i32 i64 char u16 bool
        f32 f64 string byte_buf option unit unit_struct newtype_struct map enum identifier ignored_any
    }
}

struct Access<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    len: usize,
}

impl<'de, 'a, 'b> SeqAccess<'a> for Access<'de, 'a> {
    type Error = Error;
    
    fn next_element_seed<T: DeserializeSeed<'a>>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error> {
        if self.len > 0 {
            self.len -= 1;

            let v = serde::de::DeserializeSeed::deserialize(seed, &mut *self.de)?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}
