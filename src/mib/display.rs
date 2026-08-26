#[derive(Debug, Clone, PartialEq, Eq)]
struct OctetSpec {
    // `*`: the next octet gives the repeat count.
    repeat: bool,
    length: usize,
    format: char,
    separator: Option<char>,
    terminator: Option<char>,
}

const FORMAT_CHARS: &[char] = &['a', 't', 'x', 'd', 'o', 'b'];

pub fn format_octets(hint: &str, octets: &[u8]) -> Option<String> {
    let specs = parse_octet_hint(hint)?;
    let mut out = String::new();
    let mut pos = 0usize;

    while pos < octets.len() {
        let pass_start = pos;
        for spec in &specs {
            if pos >= octets.len() {
                break;
            }
            let repeats = if spec.repeat {
                let n = octets[pos] as usize;
                pos += 1;
                n
            } else {
                1
            };

            for r in 0..repeats {
                if pos >= octets.len() {
                    break;
                }
                let take = spec.length.min(octets.len() - pos);
                render_chunk(&mut out, spec.format, &octets[pos..pos + take]);
                pos += take;
                if r + 1 < repeats && pos < octets.len() {
                    push_opt(&mut out, spec.separator);
                }
            }

            // Only emit a separator when something still follows it.
            if pos < octets.len() {
                push_opt(
                    &mut out,
                    if spec.repeat {
                        spec.terminator
                    } else {
                        spec.separator
                    },
                );
            }
        }
        // Zero-length specs would otherwise spin forever.
        if pos == pass_start {
            break;
        }
    }
    Some(out)
}

pub fn format_integer(hint: &str, value: i64) -> Option<String> {
    let mut chars = hint.chars();
    let format = chars.next()?;
    let rest: String = chars.collect();

    Some(match format {
        'd' => {
            let places = rest
                .strip_prefix('-')
                .and_then(|d| d.parse::<u32>().ok())
                .unwrap_or(0);
            format_decimal(value, places)
        }
        // RFC 2579 §3.1: "For all types, when rendering the value, leading
        // zeros are omitted" - so no padding on the integer formats.
        'x' => with_sign(value, |m| format!("{m:x}")),
        'o' => with_sign(value, |m| format!("{m:o}")),
        'b' => with_sign(value, |m| format!("{m:b}")),
        _ => return None,
    })
}

// RFC 2579 §3.1: `d-2` renders 1234 as 12.34
fn format_decimal(value: i64, places: u32) -> String {
    if places == 0 {
        return value.to_string();
    }
    // 10^19 overflows u64, and no real hint asks for that many places.
    let places = places.min(18);
    let scale = 10u64.pow(places);
    let magnitude = value.unsigned_abs();
    let sign = if value < 0 { "-" } else { "" };
    let width = places as usize;
    format!(
        "{sign}{}.{:0width$}",
        magnitude / scale,
        magnitude % scale,
        width = width
    )
}

fn with_sign(value: i64, render: impl Fn(u64) -> String) -> String {
    let body = render(value.unsigned_abs());
    if value < 0 { format!("-{body}") } else { body }
}

fn push_opt(out: &mut String, c: Option<char>) {
    if let Some(c) = c {
        out.push(c);
    }
}

fn render_chunk(out: &mut String, format: char, chunk: &[u8]) {
    match format {
        'a' => out.extend(chunk.iter().map(|b| char::from(*b))),
        't' => out.push_str(&String::from_utf8_lossy(chunk)),
        // RFC 2579 §3.1 omits leading zeros only in the integer-format
        // section; the octet-format spec states no padding rule, so pad here.
        // Net-SNMP leaves these unpadded (`0:c:29`).
        'x' => {
            for b in chunk {
                out.push_str(&format!("{b:02x}"));
            }
        }
        'd' => out.push_str(&be_integer(chunk).to_string()),
        'o' => out.push_str(&format!("{:o}", be_integer(chunk))),
        'b' => out.push_str(&format!("{:b}", be_integer(chunk))),
        _ => {}
    }
}

fn be_integer(chunk: &[u8]) -> u128 {
    chunk
        .iter()
        .take(16)
        .fold(0u128, |acc, b| (acc << 8) | u128::from(*b))
}

fn parse_octet_hint(hint: &str) -> Option<Vec<OctetSpec>> {
    let chars: Vec<char> = hint.chars().collect();
    let mut specs = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let repeat = chars[i] == '*';
        if repeat {
            i += 1;
        }

        let start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return if specs.is_empty() { None } else { Some(specs) };
        }
        let length: usize = chars[start..i].iter().collect::<String>().parse().ok()?;

        let format = chars.get(i).copied().unwrap_or(' ');
        if length == 0 || !FORMAT_CHARS.contains(&format) {
            return if specs.is_empty() { None } else { Some(specs) };
        }
        i += 1;

        let separator = take_punctuation(&chars, &mut i);
        // RFC 2579 §3.1: a repeat terminator is only meaningful after a `*`.
        let terminator = if repeat {
            take_punctuation(&chars, &mut i)
        } else {
            None
        };

        specs.push(OctetSpec {
            repeat,
            length,
            format,
            separator,
            terminator,
        });
    }

    if specs.is_empty() { None } else { Some(specs) }
}

fn take_punctuation(chars: &[char], i: &mut usize) -> Option<char> {
    let c = *chars.get(*i)?;
    if c.is_ascii_alphanumeric() || c == '*' {
        return None;
    }
    *i += 1;
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_date_and_time_hint() {
        let specs = parse_octet_hint("2d-1d-1d,1d:1d:1d.1d,1a1d:1d").unwrap();
        assert_eq!(specs.len(), 10);
        assert_eq!(
            specs[0],
            OctetSpec {
                repeat: false,
                length: 2,
                format: 'd',
                separator: Some('-'),
                terminator: None,
            }
        );
        assert_eq!(specs[7].format, 'a');
        assert_eq!(specs[7].separator, None);
        assert_eq!(specs[9].separator, None);
    }

    // RFC 2579 §2, `DateAndTime`: Tuesday May 26 1992 at 1:30:15 PM EDT.
    #[test]
    fn test_renders_rfc2579_date_and_time() {
        let octets = [0x07, 0xC8, 5, 26, 13, 30, 15, 0, b'-', 4, 0];
        assert_eq!(
            format_octets("2d-1d-1d,1d:1d:1d.1d,1a1d:1d", &octets).unwrap(),
            "1992-5-26,13:30:15.0,-4:0"
        );
    }

    #[test]
    fn test_renders_date_and_time_without_timezone() {
        let octets = [0x07, 0xC8, 5, 26, 13, 30, 15, 0];
        assert_eq!(
            format_octets("2d-1d-1d,1d:1d:1d.1d,1a1d:1d", &octets).unwrap(),
            "1992-5-26,13:30:15.0"
        );
    }

    #[test]
    fn test_renders_phys_address() {
        let octets = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        assert_eq!(format_octets("1x:", &octets).unwrap(), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_renders_display_string_as_ascii() {
        assert_eq!(format_octets("255a", b"eth0").unwrap(), "eth0");
    }

    #[test]
    fn test_repeats_the_hint_until_octets_run_out() {
        assert_eq!(format_octets("2d.", &[0, 1, 0, 2]).unwrap(), "1.2");
    }

    #[test]
    fn test_repeat_indicator_reads_its_count_from_the_data() {
        let octets = [3, b'a', b'b', b'c'];
        assert_eq!(format_octets("*1a", &octets).unwrap(), "abc");
    }

    #[test]
    fn test_repeat_group_uses_separator_between_and_terminator_after() {
        let octets = [2, 0x0A, 0x0B, 0x0C];
        assert_eq!(format_octets("*1x:;1x", &octets).unwrap(), "0a:0b;0c");
    }

    #[test]
    fn test_empty_value_renders_empty() {
        assert_eq!(format_octets("1x:", &[]).unwrap(), "");
    }

    #[test]
    fn test_octal_and_binary_octet_formats() {
        assert_eq!(format_octets("1o.", &[8, 9]).unwrap(), "10.11");
        assert_eq!(format_octets("1b.", &[5, 6]).unwrap(), "101.110");
    }

    #[test]
    fn test_unusable_hints_are_rejected() {
        assert_eq!(format_octets("", &[1]), None);
        assert_eq!(format_octets("zzz", &[1]), None);
        assert_eq!(format_integer("q", 1), None);
    }

    #[test]
    fn test_zero_length_spec_is_rejected_rather_than_looping() {
        assert_eq!(format_octets("0d", &[1, 2, 3]), None);
    }

    #[test]
    fn test_trailing_garbage_keeps_the_specs_parsed_so_far() {
        assert_eq!(format_octets("1x:??", &[0xAB, 0xCD]).unwrap(), "ab:cd");
    }

    #[test]
    fn test_integer_implied_decimal_places() {
        assert_eq!(format_integer("d-2", 1234).unwrap(), "12.34");
        assert_eq!(format_integer("d-2", 5).unwrap(), "0.05");
        assert_eq!(format_integer("d-2", -1234).unwrap(), "-12.34");
        assert_eq!(format_integer("d-3", 1000).unwrap(), "1.000");
    }

    // RFC 2579 §3.1: "For all types, when rendering the value, leading zeros
    // are omitted" - stated in the integer-format section only.
    #[test]
    fn test_integer_formats_omit_leading_zeros() {
        assert_eq!(format_integer("x", 15).unwrap(), "f");
        assert_eq!(format_integer("o", 7).unwrap(), "7");
        assert_eq!(format_integer("b", 1).unwrap(), "1");
    }

    // The octet-format spec states no padding rule, so octets stay padded.
    #[test]
    fn test_octet_format_keeps_zero_padding() {
        assert_eq!(format_octets("1x:", &[0x0C, 0x29]).unwrap(), "0c:29");
    }

    #[test]
    fn test_integer_plain_and_radix_formats() {
        assert_eq!(format_integer("d", 42).unwrap(), "42");
        assert_eq!(format_integer("x", 255).unwrap(), "ff");
        assert_eq!(format_integer("o", 8).unwrap(), "10");
        assert_eq!(format_integer("b", 5).unwrap(), "101");
        assert_eq!(format_integer("x", -255).unwrap(), "-ff");
    }
}
