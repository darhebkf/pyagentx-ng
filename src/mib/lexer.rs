use super::MibError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(String),
    Number(i128),
    Text(String),
    Bytes(Vec<u8>),
    Assign,
    Range,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Comma,
    Semicolon,
    Pipe,
    Other(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpannedToken {
    pub token: Token,
    pub line: usize,
}

pub fn tokenize(src: &str) -> Result<Vec<SpannedToken>, MibError> {
    Lexer::new(src).run()
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn run(mut self) -> Result<Vec<SpannedToken>, MibError> {
        let mut out = Vec::new();
        loop {
            self.skip_trivia();
            if self.pos >= self.src.len() {
                return Ok(out);
            }
            let line = self.line;
            let token = self.next_token()?;
            out.push(SpannedToken { token, line });
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.src.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(b) if b.is_ascii_whitespace() => {
                    self.bump();
                }
                Some(b'-') if self.peek_at(1) == Some(b'-') => self.skip_comment(),
                _ => return,
            }
        }
    }

    // ASN.1 X.680 §12.6: a comment opens with `--` and closes at the next
    // `--` or at end of line, whichever comes first.
    fn skip_comment(&mut self) {
        self.pos += 2;
        loop {
            match self.peek() {
                None | Some(b'\n') => return,
                Some(b'-') if self.peek_at(1) == Some(b'-') => {
                    self.pos += 2;
                    return;
                }
                _ => {
                    self.bump();
                }
            }
        }
    }

    fn next_token(&mut self) -> Result<Token, MibError> {
        let b = match self.peek() {
            Some(b) => b,
            None => return Err(self.err("unexpected end of input")),
        };

        match b {
            b'{' => self.single(Token::LBrace),
            b'}' => self.single(Token::RBrace),
            b'(' => self.single(Token::LParen),
            b')' => self.single(Token::RParen),
            b',' => self.single(Token::Comma),
            b';' => self.single(Token::Semicolon),
            b'|' => self.single(Token::Pipe),
            b'"' => self.lex_text(),
            b'\'' => self.lex_bytes(),
            b':' if self.starts_with(b"::=") => {
                self.pos += 3;
                Ok(Token::Assign)
            }
            b'.' if self.peek_at(1) == Some(b'.') => {
                self.pos += 2;
                Ok(Token::Range)
            }
            b'-' if matches!(self.peek_at(1), Some(d) if d.is_ascii_digit()) => self.lex_number(),
            b if b.is_ascii_digit() => self.lex_number(),
            b if b.is_ascii_alphabetic() => Ok(self.lex_word()),
            _ => {
                self.bump();
                Ok(Token::Other(b as char))
            }
        }
    }

    fn single(&mut self, token: Token) -> Result<Token, MibError> {
        self.bump();
        Ok(token)
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.src[self.pos..].starts_with(needle)
    }

    // A hyphen belongs to an identifier only when a letter or digit follows;
    // otherwise it opens a comment or stands alone (ASN.1 X.680 §12.2).
    fn lex_word(&mut self) -> Token {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else if b == b'-' && matches!(self.peek_at(1), Some(n) if n.is_ascii_alphanumeric()) {
                self.pos += 2;
            } else {
                break;
            }
        }
        Token::Word(String::from_utf8_lossy(&self.src[start..self.pos]).into_owned())
    }

    fn lex_number(&mut self) -> Result<Token, MibError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
            self.pos += 1;
        }
        let text = String::from_utf8_lossy(&self.src[start..self.pos]);
        text.parse::<i128>()
            .map(Token::Number)
            .map_err(|_| self.err(format!("number out of range: {text}")))
    }

    // A cstring may span lines; a doubled quote is a literal quote.
    fn lex_text(&mut self) -> Result<Token, MibError> {
        self.bump();
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated quoted string")),
                Some(b'"') => {
                    if self.peek() == Some(b'"') {
                        self.bump();
                        out.push(b'"');
                    } else {
                        return Ok(Token::Text(
                            String::from_utf8_lossy(&out).trim_end().to_string(),
                        ));
                    }
                }
                Some(b) => out.push(b),
            }
        }
    }

    fn lex_bytes(&mut self) -> Result<Token, MibError> {
        self.bump();
        let start = self.pos;
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated binary or hex string")),
                Some(b'\'') => break,
                _ => {}
            }
        }
        let digits: Vec<u8> = self.src[start..self.pos - 1]
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();

        let radix = self.bump();
        match radix {
            Some(b'h') | Some(b'H') => Ok(Token::Bytes(decode_hex(&digits))),
            Some(b'b') | Some(b'B') => Ok(Token::Bytes(decode_binary(&digits))),
            _ => Err(self.err("binary or hex string must end in 'H' or 'B'")),
        }
    }

    fn err(&self, message: impl Into<String>) -> MibError {
        MibError::Lex {
            line: self.line,
            message: message.into(),
        }
    }
}

// Non-hex characters are dropped. ASN.1 X.680 §12.12: an odd digit count is
// padded with a trailing zero, so `'F'H` is one octet `0xF0`.
fn decode_hex(digits: &[u8]) -> Vec<u8> {
    let nibbles: Vec<u8> = digits
        .iter()
        .filter_map(|b| (*b as char).to_digit(16).map(|d| d as u8))
        .collect();
    nibbles
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => (hi << 4) | lo,
            [hi] => hi << 4,
            _ => 0,
        })
        .collect()
}

// MSB first; a short final group is left-aligned.
fn decode_binary(digits: &[u8]) -> Vec<u8> {
    let bits: Vec<u8> = digits
        .iter()
        .filter(|b| **b == b'0' || **b == b'1')
        .map(|b| b - b'0')
        .collect();
    bits.chunks(8)
        .map(|group| {
            let mut byte = 0u8;
            for (i, bit) in group.iter().enumerate() {
                byte |= bit << (7 - i);
            }
            byte
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Token> {
        tokenize(src)
            .unwrap()
            .into_iter()
            .map(|t| t.token)
            .collect()
    }

    #[test]
    fn test_lexes_an_oid_assignment() {
        assert_eq!(
            toks("mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }"),
            vec![
                Token::Word("mib-2".into()),
                Token::Word("OBJECT".into()),
                Token::Word("IDENTIFIER".into()),
                Token::Assign,
                Token::LBrace,
                Token::Word("mgmt".into()),
                Token::Number(1),
                Token::RBrace,
            ]
        );
    }

    #[test]
    fn test_hyphen_only_joins_when_alphanumeric_follows() {
        assert_eq!(toks("mib-2"), vec![Token::Word("mib-2".into())]);
        assert_eq!(toks("ifIndex -- note"), vec![Token::Word("ifIndex".into())]);
    }

    #[test]
    fn test_comment_closes_at_second_dash_pair() {
        assert_eq!(
            toks("a -- skipped -- b"),
            vec![Token::Word("a".into()), Token::Word("b".into())]
        );
    }

    #[test]
    fn test_dashed_separator_line_is_fully_consumed() {
        assert_eq!(
            toks("-- ------------------------\nx"),
            vec![Token::Word("x".into())]
        );
        assert_eq!(toks("--------\ny"), vec![Token::Word("y".into())]);
    }

    #[test]
    fn test_negative_numbers_and_ranges() {
        assert_eq!(
            toks("(-2147483648..2147483647)"),
            vec![
                Token::LParen,
                Token::Number(-2147483648),
                Token::Range,
                Token::Number(2147483647),
                Token::RParen,
            ]
        );
    }

    #[test]
    fn test_counter64_upper_bound_survives() {
        assert_eq!(
            toks("18446744073709551615"),
            vec![Token::Number(18446744073709551615)]
        );
    }

    #[test]
    fn test_doubled_quote_is_an_escape() {
        assert_eq!(
            toks(r#""say ""hi""""#),
            vec![Token::Text(r#"say "hi""#.into())]
        );
    }

    #[test]
    fn test_multiline_text_keeps_newlines() {
        assert_eq!(toks("\"one\ntwo\""), vec![Token::Text("one\ntwo".into())]);
    }

    #[test]
    fn test_hex_and_binary_strings() {
        assert_eq!(
            toks("'DEADbeef'H"),
            vec![Token::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])]
        );
        assert_eq!(toks("'1010'B"), vec![Token::Bytes(vec![0b1010_0000])]);
        assert_eq!(toks("''H"), vec![Token::Bytes(vec![])]);
    }

    #[test]
    fn test_line_numbers_track_newlines() {
        let spanned = tokenize("a\n\nb").unwrap();
        assert_eq!(spanned[0].line, 1);
        assert_eq!(spanned[1].line, 3);
    }

    #[test]
    fn test_line_numbers_survive_multiline_strings() {
        let spanned = tokenize("\"one\ntwo\"\nafter").unwrap();
        assert_eq!(spanned[1].token, Token::Word("after".into()));
        assert_eq!(spanned[1].line, 3);
    }

    #[test]
    fn test_unterminated_string_is_an_error() {
        assert!(matches!(
            tokenize("\"never closed"),
            Err(MibError::Lex { .. })
        ));
    }
}
