use std::fmt;
use std::io::{self, Write};

pub(crate) fn write_line(arguments: fmt::Arguments<'_>) {
    handle_result(write_line_to(&mut io::stderr().lock(), arguments));
}

fn write_line_to(writer: &mut impl Write, arguments: fmt::Arguments<'_>) -> io::Result<()> {
    writeln!(writer, "{arguments}")
}

fn handle_result(result: io::Result<()>) {
    if let Err(error) = result
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        panic!("failed printing to stderr: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_result, write_line_to};
    use std::io::{self, Write};

    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broken_stderr_pipe_does_not_panic() {
        handle_result(write_line_to(&mut BrokenPipe, format_args!("diagnostic")));
    }

    #[test]
    #[should_panic(expected = "failed printing to stderr")]
    fn unexpected_stderr_error_still_panics() {
        handle_result(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
    }
}
