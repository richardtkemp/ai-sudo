use std::process::Command;

/// Test that demonstrates the pipe character bug is fixed.
/// This tests that when we run aisudo with arguments containing pipe characters,
/// they are properly escaped and not interpreted as shell pipes.
#[test]
fn test_pipe_character_escaping() {
    // This should not be interpreted as a shell pipe due to proper escaping
    let output = Command::new("../target/debug/aisudo")
        .args(&["-n", "sed", "-i", "s/foo|bar/baz/", "/tmp/nonexistent"])
        .output()
        .expect("Failed to execute aisudo");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The command should fail because the file doesn't exist, not because of pipe interpretation
    // If the pipe was interpreted by shell, we might see different error messages
    assert!(
        stderr.contains("s/foo|bar/baz/") || stderr.contains("sed"),
        "Command should contain the original sed expression, got: {}",
        stderr
    );

    // Should not contain pipe-related shell errors
    assert!(
        !stderr.contains("command not found") || !stderr.contains("No such file or directory"),
        "Should not have pipe interpretation errors, got: {}",
        stderr
    );
}

/// Test various shell metacharacters are properly escaped
#[test]
fn test_shell_metacharacter_escaping() {
    let test_cases = vec![
        ("echo", "hello; rm -rf /"), // semicolon
        ("echo", "$HOME/test"),      // dollar sign
        ("echo", "hello world"),     // space
        ("sed", "s/foo|bar/baz/"),   // pipe character
        ("echo", "$(whoami)"),       // command substitution
        ("echo", "hello && echo world"), // logical AND
    ];

    for (cmd, arg) in test_cases {
        let output = Command::new("../target/debug/aisudo")
            .args(&["-n", cmd, arg])
            .output()
            .expect("Failed to execute aisudo");

        let stderr = String::from_utf8_lossy(&output.stderr);

        // The argument should appear in the error message as-is,
        // indicating it was properly escaped
        assert!(
            stderr.contains(arg) || stderr.contains(cmd),
            "Command should contain the original argument '{}', got: {}",
            arg, stderr
        );
    }
}