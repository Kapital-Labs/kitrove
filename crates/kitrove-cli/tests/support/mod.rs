use std::io::Read;

const MAX_PROMPT_BYTES: usize = 64 * 1024;

pub(crate) fn read_until_prompt(reader: &mut impl Read, bytes: &mut Vec<u8>, prompt: &[u8]) {
    while !bytes.ends_with(prompt) {
        let mut byte = [0_u8; 1];
        assert_eq!(reader.read(&mut byte).unwrap(), 1);
        bytes.push(byte[0]);
        assert!(bytes.len() < MAX_PROMPT_BYTES);
    }
}
