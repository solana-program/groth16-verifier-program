/// Instruction tags: the first byte of every instruction's data.
///
/// Lives outside the `instruction` feature so the on-chain dispatcher can use
/// it without pulling in the client-side builders (and their `std`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    InitializeStaging = 0,
    Write = 1,
    Publish = 2,
    Verify = 3,
    CloseStaging = 4,
}

impl Tag {
    #[inline]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::InitializeStaging),
            1 => Some(Self::Write),
            2 => Some(Self::Publish),
            3 => Some(Self::Verify),
            4 => Some(Self::CloseStaging),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_unknown() {
        for tag in [
            Tag::InitializeStaging,
            Tag::Write,
            Tag::Publish,
            Tag::Verify,
            Tag::CloseStaging,
        ] {
            assert_eq!(Tag::from_u8(tag as u8), Some(tag));
        }
        assert_eq!(Tag::from_u8(5), None);
        assert_eq!(Tag::from_u8(0xff), None);
    }
}
