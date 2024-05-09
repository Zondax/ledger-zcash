pub struct Bitstreamer<'a> {
    pub input_bytes: &'a [u8],
    pub byte_index: usize,
    pub bitsize: u32,
    pub bit_index: u32,
    pub curr: u32,
    pub shift: i8,
    pub carry: i8,
}

impl<'a> Bitstreamer<'a> {
    #[inline(never)]
    fn peek(&self) -> bool {
        self.bit_index < self.bitsize
    }
}

impl<'a> Iterator for Bitstreamer<'a> {
    type Item = u8;

    /**
     * Retrieves the next group of 3 bits from the bitstream.
     *
     * This method extracts the next group of 3 bits from the current position in the bitstream.
     * It handles the bit and byte indexing, including the necessary shifts and carries
     * when the end of the current byte is reached.
     *
     * @returns An `Option<u8>` which is `None` if the end of the stream is reached, or `Some(u8)` with the next group of 3 bits.
     */
    #[inline(never)]
    fn next(&mut self) -> Option<u8> {
        // Check if the current bit index has reached the total bitsize or if the byte index has exceeded the input bytes length.
        if self.bit_index >= self.bitsize || self.byte_index >= self.input_bytes.len() {
            return None;
        }

        // Extract the next 3 bits from the current position in the bitstream.
        let s = ((self.curr >> (self.shift as u32)) & 7) as u8;

        // Increment the bit index by 3 as we have read 3 bits.
        self.bit_index += 3;

        // Check if the shift needs to be adjusted because it goes negative.
        if self.shift - 3 < 0 {
            // Move to the next byte in the input stream.
            self.byte_index += 1;

            // Check if the new byte index is still within the bounds of the input bytes.
            if self.byte_index < self.input_bytes.len() {
                // Adjust the carry to cycle through 0, 1, 2.
                self.carry = ((self.carry - 1) + 3) % 3;

                // Shift the current bits left by 8 bits to make room for the new byte.
                self.curr <<= 8;

                // Add the new byte to the current integer.
                self.curr += self.input_bytes[self.byte_index] as u32;

                // Calculate the new shift value based on the carry.
                self.shift = 5 + self.carry;
            } else {
                // Calculate the shift needed to adjust the current bits when no more bytes are available.
                let sh =
                    (((self.carry & 2) + ((self.carry & 2) >> 1)) ^ (self.carry & 1) ^ 1) as u32;

                // Shift the current bits left by the calculated shift amount.
                self.curr <<= sh;

                // Reset the shift to 0 as no more bytes are available.
                self.shift = 0;
            }
        } else {
            // Simply reduce the shift by 3 if it does not go negative.
            self.shift -= 3;
        }

        // Return the extracted bits as a byte.
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peek() {
        let data = [0b10101010, 0b11001100];
        let streamer = Bitstreamer {
            input_bytes: &data,
            byte_index: 0,
            bitsize: 16,
            bit_index: 0,
            curr: 0b1010101011001100,
            shift: 8,
            carry: 0,
        };
        assert!(streamer.peek());
    }

    #[test]
    fn test_next() {
        let data = [0b10101010, 0b11001100];
        let mut streamer = Bitstreamer {
            input_bytes: &data,
            byte_index: 0,
            bitsize: 16,
            bit_index: 0,
            curr: 0b1010101011001100,
            shift: 8,
            carry: 0,
        };

        let expected_outputs = [2, 6, 3, 1, 4, 6];

        for &expected in expected_outputs.iter() {
            let received = streamer.next();
            assert_eq!(
                received,
                Some(expected),
                "Expected value: {:?}, but received: {:?}",
                Some(expected),
                received
            );
        }

        assert_eq!(streamer.next(), None);
    }
}
