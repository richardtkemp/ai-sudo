//! How a sudo command is laid out for the approver (#2874).
//!
//! A compound request reads as one long line, so the approver cannot see how
//! many commands it holds. [`display_command`] puts a line break after each
//! separator that really ends a command.
//!
//! The command is caller-controlled and may be hostile, so the one safety rule
//! here is structural: this code only ever inserts `\n`. It never drops,
//! replaces or reorders a character, whatever the input. A wrong guess by the
//! lexer costs a line break, and never hides text. The output is for showing
//! only: what runs and what the audit log stores is `record.command`.
//!
//! A human-approved command runs under a real `sh -c` (`exec_command`), so the
//! lexing follows the shell and not `parse_command_chain`.

/// Shells whose `-c` argument is a script, so its separators count too.
const SCRIPT_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash"];

/// The language of a script passed as an argument. Each one says which option
/// introduces the script. Dick's ruling: interpreted scripts get line breaks too.
#[derive(Clone, Copy, PartialEq)]
enum ScriptLang {
    Shell,
    Python,
    PerlRubyLua,
    Node,
    Php,
}

impl ScriptLang {
    /// The language run by the program called `name`, if it takes a script.
    fn of_program(name: &str) -> Option<Self> {
        if SCRIPT_SHELLS.contains(&name) || matches!(name, "su" | "runuser") {
            Some(Self::Shell)
        } else if name.starts_with("python") {
            Some(Self::Python)
        } else if matches!(name, "perl" | "ruby" | "lua") {
            Some(Self::PerlRubyLua)
        } else if matches!(name, "node" | "nodejs") {
            Some(Self::Node)
        } else if name == "php" {
            Some(Self::Php)
        } else {
            None
        }
    }

    /// True if the option `word` means "the next word is the script".
    fn is_script_option(self, word: &str) -> bool {
        let short = word.starts_with('-') && !word.starts_with("--");
        match self {
            Self::Shell => short && word.contains('c'),
            Self::Python => short && word.ends_with('c'),
            Self::PerlRubyLua => short && (word.ends_with('e') || word.ends_with('E')),
            Self::Node => matches!(word, "-e" | "-p" | "-pe" | "--eval" | "--print"),
            Self::Php => word == "-r",
        }
    }
}

/// `sh -c "sh -c '...'"` nesting beyond this shows without inner line breaks.
/// Each level walks a smaller slice once, so the cost stays linear.
const MAX_SCRIPT_DEPTH: usize = 8;

/// `command` with a line break after each command-ending separator.
pub(crate) fn display_command(command: &str) -> String {
    let chars: Vec<char> = command.chars().collect();
    let mut breaks = break_points(&chars, 0);
    breaks.sort_unstable();
    breaks.dedup();

    let mut out = String::with_capacity(command.len() + breaks.len());
    let mut next = breaks.iter().copied().peekable();
    for (i, c) in chars.iter().enumerate() {
        if next.next_if_eq(&i).is_some() {
            out.push('\n');
        }
        out.push(*c);
    }
    out
}

/// Where the lexer is nested, innermost last. An empty stack is the top level
/// of the script, the only place a separator splits the display: a command
/// substitution is one word of the command around it.
#[derive(PartialEq)]
enum Nest {
    DoubleQuote,
    Substitution,
    Backtick,
}

/// Progress towards recognising `<shell> [options] -c <script>` in the words of
/// one simple command.
#[derive(PartialEq)]
enum ScriptWatch {
    Idle,
    /// `keep_going`: `su` and `runuser` take a user name before `-c`, so a word
    /// that is not an option does not end the search.
    AfterProgram {
        lang: ScriptLang,
        keep_going: bool,
    },
    OptionArgument(ScriptLang),
    ExpectScript(ScriptLang),
}

/// The indexes in `s` that get a line break before them.
fn break_points(s: &[char], depth: usize) -> Vec<usize> {
    let mut breaks = Vec::new();
    let mut nest: Vec<Nest> = Vec::new();
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut watch = ScriptWatch::Idle;
    let mut word_start: Option<usize> = None;
    let mut i = 0;

    while i < s.len() {
        let c = s[i];
        let next = s.get(i + 1).copied();

        if c == '\\' {
            word_start.get_or_insert(i);
            i += 2;
            continue;
        }

        if nest.last() == Some(&Nest::DoubleQuote) {
            match (c, next) {
                ('"', _) => {
                    nest.pop();
                }
                ('$', Some('(')) => {
                    nest.push(Nest::Substitution);
                    i += 1;
                }
                ('`', _) => nest.push(Nest::Backtick),
                _ => {}
            }
            i += 1;
            continue;
        }

        match c {
            '\'' => {
                word_start.get_or_insert(i);
                i = closing_single_quote(s, i);
                continue;
            }
            '"' => {
                word_start.get_or_insert(i);
                nest.push(Nest::DoubleQuote);
                i += 1;
                continue;
            }
            '$' if next == Some('(') => {
                word_start.get_or_insert(i);
                nest.push(Nest::Substitution);
                i += 2;
                continue;
            }
            '`' => {
                word_start.get_or_insert(i);
                if nest.last() == Some(&Nest::Backtick) {
                    nest.pop();
                } else {
                    nest.push(Nest::Backtick);
                }
                i += 1;
                continue;
            }
            _ => {}
        }

        if nest.last() == Some(&Nest::Substitution) {
            match c {
                '(' => nest.push(Nest::Substitution),
                ')' => {
                    nest.pop();
                }
                _ => {}
            }
        }

        let is_word_char = !c.is_whitespace() && !";|&<>()".contains(c);
        if is_word_char {
            if c == '#' && word_start.is_none() {
                // A comment runs to the line end, and its apostrophes are not quotes.
                while i < s.len() && s[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            word_start.get_or_insert(i);
            i += 1;
            continue;
        }

        // A word has ended, unless this is inside a substitution, which is
        // all one word of the outer command.
        if nest.is_empty() {
            if let Some(start) = word_start.take() {
                watch_word(s, start, i, depth, &mut watch, &mut breaks);
            }
        }

        if c == '\n' {
            i = skip_heredoc_bodies(s, i + 1, &mut heredocs);
            if nest.is_empty() {
                watch = ScriptWatch::Idle;
            }
            continue;
        }

        if c == '<' && next == Some('<') {
            if s.get(i + 2) == Some(&'<') {
                i += 3; // A here-string has no body.
            } else {
                i = read_heredoc_delimiter(s, i + 2, &mut heredocs);
            }
            continue;
        }

        let separator = separator_len(s, i);
        if separator == 0 {
            i += 1;
            continue;
        }
        i += separator;
        if nest.is_empty() {
            watch = ScriptWatch::Idle;
            let mut after = i;
            while matches!(s.get(after), Some(' ' | '\t')) {
                after += 1;
            }
            // Nothing follows, or the author's own line break already does.
            let ends_line = match s.get(after) {
                None | Some('\n') => true,
                Some('\\') => s.get(after + 1) == Some(&'\n'),
                _ => false,
            };
            if !ends_line {
                breaks.push(after);
            }
        }
    }

    if nest.is_empty() {
        if let Some(start) = word_start {
            watch_word(s, start, s.len(), depth, &mut watch, &mut breaks);
        }
    }
    breaks
}

/// The length of the command-ending separator at `s[i]`, or 0 if there is none.
///
/// `|` and `&` count as well as `;`, `&&` and `||`: each stage of a pipeline and
/// each background job is a separate command that runs as root, and the daemon
/// already treats a pipe stage as its own segment. Redirections such as `2>&1`,
/// `&>f` and `>|f` are not separators.
fn separator_len(s: &[char], i: usize) -> usize {
    let next = s.get(i + 1).copied();
    let prev = i.checked_sub(1).map(|p| s[p]);
    match s[i] {
        ';' => match (next, s.get(i + 2)) {
            (Some(';'), Some('&')) => 3,
            (Some(';' | '&'), _) => 2,
            _ => 1,
        },
        '|' if prev == Some('>') => 0,
        '|' if matches!(next, Some('|' | '&')) => 2,
        '|' => 1,
        '&' if matches!(prev, Some('>' | '<')) || next == Some('>') => 0,
        '&' if next == Some('&') => 2,
        '&' => 1,
        _ => 0,
    }
}

/// The index just past the single quote that closes the one at `s[open]`.
fn closing_single_quote(s: &[char], open: usize) -> usize {
    s[open + 1..]
        .iter()
        .position(|&c| c == '\'')
        .map_or(s.len(), |n| open + n + 2)
}

/// Advance the `-c` watch by one finished word. A script argument's own break
/// points are mapped back to indexes in `s`.
fn watch_word(
    s: &[char],
    start: usize,
    end: usize,
    depth: usize,
    watch: &mut ScriptWatch,
    breaks: &mut Vec<usize>,
) {
    let (value, origin) = word_value(s, start, end);
    let text: String = value.iter().collect();
    *watch = match *watch {
        ScriptWatch::ExpectScript(lang) => {
            if depth < MAX_SCRIPT_DEPTH {
                let inner = match lang {
                    ScriptLang::Shell => break_points(&value, depth + 1),
                    _ => statement_breaks(&value, lang),
                };
                // A compound script also starts on its own line, so its commands
                // line up (Dick's ruling). A one-command script stays on one line:
                // it would otherwise look like two commands in the compact view.
                if !inner.is_empty()
                    && matches!(s[start], '\'' | '"')
                    && !starts_with_line_break(&s[start + 1..end])
                {
                    breaks.push(start + 1);
                }
                breaks.extend(inner.into_iter().map(|b| origin[b]));
            }
            ScriptWatch::Idle
        }
        ScriptWatch::OptionArgument(lang) => ScriptWatch::AfterProgram {
            lang,
            keep_going: false,
        },
        ScriptWatch::AfterProgram { lang, keep_going } => {
            if lang.is_script_option(&text) {
                ScriptWatch::ExpectScript(lang)
            } else if lang == ScriptLang::Shell
                && matches!(text.as_str(), "-o" | "+o" | "-O" | "+O")
            {
                ScriptWatch::OptionArgument(lang)
            } else if keep_going || text.starts_with('-') || text.starts_with('+') {
                ScriptWatch::AfterProgram { lang, keep_going }
            } else {
                ScriptWatch::Idle
            }
        }
        ScriptWatch::Idle => {
            let name = text.rsplit('/').next().unwrap_or("");
            match ScriptLang::of_program(name) {
                Some(lang) => ScriptWatch::AfterProgram {
                    lang,
                    keep_going: matches!(name, "su" | "runuser"),
                },
                None => ScriptWatch::Idle,
            }
        }
    };
}

/// The break points of a script in a language other than shell: after each `;`
/// outside a string, a comment and round or square brackets (`for (;;)`). `|` and
/// `&` are operators in these languages, so they do not count.
fn statement_breaks(s: &[char], lang: ScriptLang) -> Vec<usize> {
    let mut breaks = Vec::new();
    let mut brackets = 0usize;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let comment = if lang == ScriptLang::Node || lang == ScriptLang::Php {
            c == '/' && s.get(i + 1) == Some(&'/')
        } else {
            c == '#'
        };
        if comment {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                i += 1;
                while i < s.len() && s[i] != c {
                    i += if s[i] == '\\' { 2 } else { 1 };
                }
            }
            '(' | '[' => brackets += 1,
            ')' | ']' => brackets = brackets.saturating_sub(1),
            ';' if brackets == 0 => {
                let mut after = i + 1;
                while matches!(s.get(after), Some(' ' | '\t')) {
                    after += 1;
                }
                if !matches!(s.get(after), None | Some('\n')) {
                    breaks.push(after);
                }
            }
            _ => {}
        }
        i += 1;
    }
    breaks
}

/// True if `s` holds nothing but blanks before its first line break.
fn starts_with_line_break(s: &[char]) -> bool {
    s.iter().find(|c| !matches!(c, ' ' | '\t')) == Some(&'\n')
}

/// What the shell makes of the word `s[start..end]` once it has removed the
/// quotes, and for each character of that the index in `s` it came from.
fn word_value(s: &[char], start: usize, end: usize) -> (Vec<char>, Vec<usize>) {
    let mut value = Vec::with_capacity(end - start);
    let mut origin = Vec::with_capacity(end - start);
    let mut quote: Option<char> = None;
    let mut i = start;
    while i < end {
        let c = s[i];
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), _) if q == c => quote = None,
            (None, '\\') | (Some('"'), '\\') if i + 1 < end => {
                // Inside double quotes the backslash only escapes these.
                let escapes = quote.is_none() || "\"\\$`\n".contains(s[i + 1]);
                if escapes {
                    value.push(s[i + 1]);
                    origin.push(i);
                    i += 2;
                    continue;
                }
                value.push(c);
                origin.push(i);
            }
            _ => {
                value.push(c);
                origin.push(i);
            }
        }
        i += 1;
    }
    (value, origin)
}

/// Record the delimiter of the heredoc whose `<<` ends just before `s[i]`, and
/// return the index just past the delimiter word.
fn read_heredoc_delimiter(s: &[char], mut i: usize, heredocs: &mut Vec<(String, bool)>) -> usize {
    let strip_tabs = s.get(i) == Some(&'-');
    if strip_tabs {
        i += 1;
    }
    while matches!(s.get(i), Some(' ' | '\t')) {
        i += 1;
    }
    let mut delimiter = String::new();
    let mut quote: Option<char> = None;
    while let Some(&c) = s.get(i) {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), _) if q == c => quote = None,
            (None, '\\') => {
                i += 1;
                if let Some(&escaped) = s.get(i) {
                    delimiter.push(escaped);
                }
            }
            (None, _) if c.is_whitespace() || ";|&<>()".contains(c) => break,
            _ => delimiter.push(c),
        }
        i += 1;
    }
    if !delimiter.is_empty() {
        heredocs.push((delimiter, strip_tabs));
    }
    i
}

/// Skip the bodies of the pending heredocs, which start at the line at `s[i]`.
/// An unterminated body runs to the end of the input, as it does in the shell.
fn skip_heredoc_bodies(s: &[char], mut i: usize, heredocs: &mut Vec<(String, bool)>) -> usize {
    for (delimiter, strip_tabs) in heredocs.drain(..) {
        while i < s.len() {
            let end = s[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(s.len(), |n| i + n);
            let line: String = s[i..end].iter().collect();
            let line = if strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line.as_str()
            };
            let matched = line == delimiter;
            i = (end + 1).min(s.len());
            if matched {
                break;
            }
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security rule: `shown` is `original` plus line breaks, nothing else.
    fn assert_only_line_breaks_added(original: &str, shown: &str) {
        let mut rest = original.chars().peekable();
        for c in shown.chars() {
            if rest.peek() == Some(&c) {
                rest.next();
            } else {
                assert_eq!(c, '\n', "changed a character: {original:?} -> {shown:?}");
            }
        }
        assert_eq!(rest.next(), None, "dropped text: {original:?} -> {shown:?}");
    }

    #[track_caller]
    fn check(input: &str, want: &str) {
        let got = display_command(input);
        assert_eq!(got, want, "input: {input}");
        assert_only_line_breaks_added(input, &got);
    }

    /// The input must show exactly as it is.
    #[track_caller]
    fn unchanged(input: &str) {
        check(input, input);
    }

    #[test]
    fn dicks_example() {
        check("ls / ; rm -rf /", "ls / ; \nrm -rf /");
    }

    #[test]
    fn a_plain_command_is_untouched() {
        unchanged("ls /root");
        unchanged("");
    }

    #[test]
    fn each_separator_ends_a_line() {
        check("a; b", "a; \nb");
        check("a;b", "a;\nb");
        check("a && b", "a && \nb");
        check("a || b", "a || \nb");
        check("a | b", "a | \nb");
        check("a |& b", "a |& \nb");
        check("a & b", "a & \nb");
        check("a && b || c ; d | e", "a && \nb || \nc ; \nd | \ne");
    }

    #[test]
    fn a_trailing_separator_adds_no_empty_line() {
        unchanged("a &");
        unchanged("a ;  ");
    }

    #[test]
    fn the_authors_own_line_break_is_not_doubled() {
        unchanged("a &&\nb");
        unchanged("a ; \nb");
        unchanged("a && \\\n  b");
    }

    #[test]
    fn quoted_or_escaped_separators_do_not_split() {
        unchanged("echo 'a; b'");
        unchanged("echo \"a && b\"");
        unchanged("echo a\\;b");
        unchanged("find . -name x -exec rm {} \\;");
        check(
            "find . -exec rm {} \\; ; ls",
            "find . -exec rm {} \\; ; \nls",
        );
        unchanged(r#"echo "a \" ; b""#);
        unchanged("echo 'it'\\''s; fine'");
    }

    #[test]
    fn redirections_are_not_separators() {
        unchanged("a 2>&1");
        unchanged("a &> f");
        unchanged("a <&3");
        unchanged("a >| f");
        check("a 2>&1 | b", "a 2>&1 | \nb");
    }

    #[test]
    fn a_command_substitution_is_one_word() {
        unchanged("echo $(a; b)");
        unchanged("echo $(a $(b; c); d)");
        unchanged("echo `a; b`");
        unchanged("echo \"$(a \"x; y\"; b)\"");
        check("echo $(a; b); c", "echo $(a; b); \nc");
        check("echo `a; b` && c", "echo `a; b` && \nc");
    }

    #[test]
    fn comments_do_not_split_and_their_apostrophes_are_not_quotes() {
        unchanged("a # b; c");
        check("a # it's\nb; c", "a # it's\nb; \nc");
        // A # inside a word is not a comment.
        check("a b#c; d", "a b#c; \nd");
    }

    #[test]
    fn a_heredoc_body_does_not_split() {
        unchanged("cat <<EOF\na; b\nEOF");
        check(
            "cat <<'EOF'\na; b\nEOF\nc; d",
            "cat <<'EOF'\na; b\nEOF\nc; \nd",
        );
        check(
            "cat <<-E\n\ta; b\n\tE\nc; d",
            "cat <<-E\n\ta; b\n\tE\nc; \nd",
        );
        check("cat <<< 'a'; b", "cat <<< 'a'; \nb");
        // An unterminated body runs to the end, as it does in the shell.
        unchanged("cat <<EOF\na; b");
    }

    #[test]
    fn dicks_ruling_on_a_shell_wrapper() {
        check("sh -c 'a; b'", "sh -c '\na; \nb'");
    }

    #[test]
    fn a_shell_c_script_shows_its_commands_on_lines() {
        check("bash -c \"a && b\"", "bash -c \"\na && \nb\"");
        check("zsh -c 'a; b'", "zsh -c '\na; \nb'");
        check("/bin/bash -lc 'a; b'", "/bin/bash -lc '\na; \nb'");
        check("bash -l -c 'a; b'", "bash -l -c '\na; \nb'");
        check("bash --norc -c 'a; b'", "bash --norc -c '\na; \nb'");
        check(
            "bash -o pipefail -c 'a; b'",
            "bash -o pipefail -c '\na; \nb'",
        );
        check("env X=1 sh -c 'a; b'", "env X=1 sh -c '\na; \nb'");
        check("sh -c 'a; b' && c", "sh -c '\na; \nb' && \nc");
        // Quotes in the script keep their meaning.
        unchanged("sh -c 'echo \"a; b\"'");
        check(
            "sh -c 'echo '\\''a; b'\\''; c'",
            "sh -c '\necho '\\''a; b'\\''; \nc'",
        );
        // A substitution in the script does not end the script word.
        check("sh -c \"a $(b c); d\"", "sh -c \"\na $(b c); \nd\"");
        check(
            "sh -c \"echo \\\"a; b\\\"; c\"",
            "sh -c \"\necho \\\"a; b\\\"; \nc\"",
        );
        // Nesting.
        check("sh -c \"sh -c 'a; b'\"", "sh -c \"\nsh -c '\na; \nb'\"");
        // Without an opening quote there is nothing to break after.
        check("sh -c a;b", "sh -c a;\nb");
    }

    #[test]
    fn a_one_command_script_stays_on_one_line() {
        unchanged("sh -c 'ls /'");
        unchanged("bash -c \"ls /\"");
    }

    #[test]
    fn a_script_that_already_starts_on_its_own_line_is_not_doubled() {
        check("sh -c '\na; b'", "sh -c '\na; \nb'");
        check("sh -c ' \t\na; b'", "sh -c ' \t\na; \nb'");
    }

    #[test]
    fn a_heredoc_in_a_script_does_not_split() {
        unchanged("bash -c 'cat > f <<EOF\na; b\nEOF'");
    }

    #[test]
    fn interpreter_scripts_get_line_breaks_too() {
        check("python3 -c 'a; b'", "python3 -c '\na; \nb'");
        check("python3.11 -uc 'a; b'", "python3.11 -uc '\na; \nb'");
        check(
            "/usr/bin/python -c \"a; b\"",
            "/usr/bin/python -c \"\na; \nb\"",
        );
        check("perl -e 'a; b'", "perl -e '\na; \nb'");
        check("perl -pe 'a; b' f", "perl -pe '\na; \nb' f");
        check("ruby -e 'a; b'", "ruby -e '\na; \nb'");
        check("node -e 'a; b'", "node -e '\na; \nb'");
        check("node --eval 'a; b'", "node --eval '\na; \nb'");
        check("php -r 'a; b;'", "php -r '\na; \nb;'");
        check("python3 -c 'a; b'; c", "python3 -c '\na; \nb'; \nc");
        // Through a shell wrapper.
        check(
            "sh -c \"python3 -c 'a; b'\"",
            "sh -c \"\npython3 -c '\na; \nb'\"",
        );
    }

    #[test]
    fn an_interpreter_script_splits_only_at_its_own_statements() {
        unchanged("python3 -c 'print(1)'");
        // Strings, comments and brackets.
        unchanged("python3 -c 'print(\"a; b\")'");
        unchanged("python3 -c 'a # b; c'");
        unchanged("node -e 'a // b; c'");
        unchanged("node -e 'for (i = 0; i < 3; i++) x'");
        unchanged("node -e 'x = `a; b`'");
        // | and & are operators in these languages, not command separators.
        unchanged("python3 -c 'x = a | b & c'");
        // Only the script option counts.
        unchanged("python3 script.py 'a; b'");
        unchanged("python3 -m tool 'a; b'");
        unchanged("perl -I 'a; b'");
    }

    #[test]
    fn su_and_runuser_scripts_get_line_breaks_too() {
        check("su -c 'a; b' rich", "su -c '\na; \nb' rich");
        check("su - rich -c 'a; b'", "su - rich -c '\na; \nb'");
        check("runuser -l rich -c 'a; b'", "runuser -l rich -c '\na; \nb'");
    }

    #[test]
    fn only_the_script_argument_of_a_shell_splits() {
        unchanged("sh script.sh 'a; b'");
        unchanged("sh -x script.sh 'a; b'");
        unchanged("ls -c 'a; b'");
        unchanged("sh -c 'a' 'b; c'");
    }

    #[test]
    fn a_backslash_quote_outside_quotes_cannot_disguise_a_command() {
        // `sh -c` runs three commands.
        check(
            "ls \\' ; rm -rf / ; echo \\'",
            "ls \\' ; \nrm -rf / ; \necho \\'",
        );
    }

    #[test]
    fn hostile_input_keeps_every_character() {
        for input in [
            "echo 'unterminated ; rm -rf /",
            "echo \"unterminated ; rm -rf /",
            "echo $(unterminated ; rm -rf /",
            "echo `unterminated ; rm -rf /",
            "sh -c 'unterminated ; rm -rf /",
            "python3 -c 'unterminated ; rm -rf /",
            "node -e `a; b",
            "perl -e \"a\\",
            "sh -c",
            "sh -c ",
            "sh -c \\",
            "\\",
            "a \\",
            "a; \\",
            ";;;;&&&&||||",
            "$($($($(",
            "<<",
            "<<-",
            "<<'",
            "a <<E; b\n",
            "\u{202e}a; b\u{202c}; c",
            "é; ü && 日本語",
        ] {
            assert_only_line_breaks_added(input, &display_command(input));
        }
    }

    #[test]
    fn long_input_and_deep_nesting_stay_fast_and_intact() {
        let cases = [
            "a; ".repeat(200_000),
            "$(".repeat(200_000),
            "'".repeat(200_001),
            "<<E\n".repeat(50_000),
            format!("{}a; b", "sh -c \"".repeat(2_000)),
        ];
        let started = std::time::Instant::now();
        for input in &cases {
            assert_only_line_breaks_added(input, &display_command(input));
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "took {:?}",
            started.elapsed()
        );
    }

    /// Random shell-shaped text, from a fixed seed so a failure repeats.
    #[test]
    fn random_input_only_ever_gains_line_breaks() {
        let pieces = [
            ";",
            "&",
            "&&",
            "|",
            "||",
            "'",
            "\"",
            "\\",
            "`",
            "$(",
            "(",
            ")",
            "<<",
            "<<-",
            "E",
            "\n",
            " ",
            "\t",
            "#",
            "a",
            "sh",
            "-c",
            "bash -c '",
            "python3 -c '",
            "perl -e '",
            "node -e '",
            "su -c '",
            ">",
            "é",
            "\u{202e}",
        ];
        let mut state: u64 = 0x2874;
        let mut roll = |n: usize| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((state >> 33) as usize) % n
        };
        for _ in 0..50_000 {
            let input: String = (0..roll(24)).map(|_| pieces[roll(pieces.len())]).collect();
            assert_only_line_breaks_added(&input, &display_command(&input));
        }
    }
}
