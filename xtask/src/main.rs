use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use rustty_core::{ALL_TOOLS, NEXT_RELEASE_NOTES_PATH, SUITE_CHANGELOG_PATH};

const REQUIRED_FILES: &[&str] = &[
    "README.adoc",
    "CONTRIBUTING.adoc",
    "NOTICE.adoc",
    "LICENSE",
    "CHANGELOG.adoc",
    "docs/index.adoc",
    "docs/architecture/overview.adoc",
    "docs/architecture/config-model.adoc",
    "docs/architecture/repository-workflow.adoc",
    "docs/architecture/release-process.adoc",
    "docs/architecture/workspace-layout.adoc",
    "docs/migration/putty-compatibility.adoc",
    "docs/migration/session-import.adoc",
    "docs/migration/key-import.adoc",
    "docs/legal/licensing.adoc",
    "docs/release-notes/next.adoc",
    "docs/release-notes/0.1.0.adoc",
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let command = env::args().nth(1).unwrap_or_else(|| "ci".to_owned());
    match command.as_str() {
        "ci" | "check-docs" => {
            check_required_files()?;
            check_tool_coverage()?;
            check_doc_extension_policy()?;
            check_xref_targets()?;
            check_release_note_links()?;
            if let Ok(branch_name) = env::var("RUSTTY_BRANCH_NAME") {
                check_branch_name(&branch_name)?;
            }
            println!("RusTTY repository checks passed.");
            Ok(())
        }
        "check-branch" => {
            let branch_name = env::args()
                .nth(2)
                .or_else(|| env::var("RUSTTY_BRANCH_NAME").ok())
                .ok_or_else(|| "check-branch requires a branch name".to_owned())?;
            check_branch_name(&branch_name)
        }
        other => Err(format!("unsupported xtask command: {other}")),
    }
}

fn check_required_files() -> Result<(), String> {
    for path in REQUIRED_FILES {
        if !Path::new(path).exists() {
            return Err(format!("missing required file: {path}"));
        }
    }

    Ok(())
}

fn check_tool_coverage() -> Result<(), String> {
    for tool in ALL_TOOLS {
        if !Path::new(tool.doc_path).exists() {
            return Err(format!("missing tool manual: {}", tool.doc_path));
        }

        if !Path::new(tool.changelog_path).exists() {
            return Err(format!("missing tool changelog: {}", tool.changelog_path));
        }
    }

    if !Path::new(SUITE_CHANGELOG_PATH).exists() {
        return Err(format!("missing suite changelog: {SUITE_CHANGELOG_PATH}"));
    }

    if !Path::new(NEXT_RELEASE_NOTES_PATH).exists() {
        return Err(format!(
            "missing draft release notes: {NEXT_RELEASE_NOTES_PATH}"
        ));
    }

    Ok(())
}

fn check_xref_targets() -> Result<(), String> {
    let adoc_files = gather_adoc_files(Path::new("."))?;
    for file in adoc_files {
        let content =
            fs::read_to_string(&file).map_err(|error| format!("{}: {error}", file.display()))?;
        for xref in find_xrefs(&content) {
            let Some((target_path, _anchor)) = split_target(&xref) else {
                continue;
            };
            if target_path.is_empty() {
                continue;
            }

            let resolved = file
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target_path)
                .normalize();
            if !resolved.exists() {
                return Err(format!("{}: broken xref target '{}'", file.display(), xref));
            }
        }
    }

    Ok(())
}

fn check_doc_extension_policy() -> Result<(), String> {
    for forbidden in ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "NOTICE.md"] {
        if Path::new(forbidden).exists() {
            return Err(format!(
                "human-facing project docs must use AsciiDoc, found forbidden file: {forbidden}"
            ));
        }
    }

    if let Some(file) = gather_files_with_extension(Path::new("docs"), OsStr::new("md"))?
        .into_iter()
        .next()
    {
        return Err(format!(
            "human-facing docs under docs/ must use AsciiDoc, found: {}",
            file.display()
        ));
    }

    Ok(())
}

fn check_release_note_links() -> Result<(), String> {
    let release_note_paths = [
        Path::new("docs/release-notes/next.adoc"),
        Path::new("docs/release-notes/0.1.0.adoc"),
    ];

    for release_note in release_note_paths {
        let content = fs::read_to_string(release_note)
            .map_err(|error| format!("{}: {error}", release_note.display()))?;
        let mut found_changelog_link = false;

        for xref in find_xrefs(&content) {
            let Some((target_path, anchor)) = split_target(&xref) else {
                continue;
            };
            if !target_path.contains("../changelogs/") {
                continue;
            }

            found_changelog_link = true;
            let resolved = release_note
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target_path)
                .normalize();
            let anchor = anchor.ok_or_else(|| {
                format!(
                    "{}: changelog xref is missing an anchor: {xref}",
                    release_note.display()
                )
            })?;
            let changelog = fs::read_to_string(&resolved)
                .map_err(|error| format!("{}: {error}", resolved.display()))?;
            let expected_anchor = format!("[#{anchor}]");
            if !changelog.contains(&expected_anchor) {
                return Err(format!(
                    "{}: missing changelog anchor '{}' in {}",
                    release_note.display(),
                    anchor,
                    resolved.display()
                ));
            }
        }

        if !found_changelog_link {
            return Err(format!(
                "{}: expected at least one changelog xref",
                release_note.display()
            ));
        }
    }

    Ok(())
}

fn check_branch_name(branch_name: &str) -> Result<(), String> {
    if branch_name == "main" {
        return Ok(());
    }

    let Some((prefix, remainder)) = branch_name.split_once('/') else {
        return Err(format!(
            "invalid branch name '{branch_name}': missing category prefix"
        ));
    };

    let allowed_prefix = matches!(
        prefix,
        "feat" | "fix" | "docs" | "chore" | "release" | "hotfix"
    );
    if !allowed_prefix {
        return Err(format!(
            "invalid branch name '{branch_name}': unsupported prefix '{prefix}'"
        ));
    }

    if remainder.is_empty() {
        return Err(format!(
            "invalid branch name '{branch_name}': missing descriptive suffix"
        ));
    }

    if !remainder.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '/' | '.')
    }) {
        return Err(format!(
            "invalid branch name '{branch_name}': only lowercase letters, digits, '.', '/', and '-' are allowed"
        ));
    }

    Ok(())
}

fn gather_adoc_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    gather_adoc_files_inner(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn gather_files_with_extension(root: &Path, extension: &OsStr) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    gather_files_with_extension_inner(root, extension, &mut files)?;
    files.sort();
    Ok(files)
}

fn gather_adoc_files_inner(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|error| format!("{}: {error}", root.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        let path = entry.path();
        if path
            .components()
            .any(|component| component.as_os_str() == OsStr::new(".git"))
        {
            continue;
        }

        if path.is_dir() {
            gather_adoc_files_inner(&path, files)?;
        } else if path.extension() == Some(OsStr::new("adoc")) {
            files.push(path);
        }
    }

    Ok(())
}

fn gather_files_with_extension_inner(
    root: &Path,
    extension: &OsStr,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(root).map_err(|error| format!("{}: {error}", root.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        let path = entry.path();
        if path.is_dir() {
            gather_files_with_extension_inner(&path, extension, files)?;
        } else if path.extension() == Some(extension) {
            files.push(path);
        }
    }

    Ok(())
}

fn find_xrefs(content: &str) -> Vec<String> {
    let mut xrefs = Vec::new();
    let mut remaining = content;
    while let Some(index) = remaining.find("xref:") {
        remaining = &remaining[index + 5..];
        if let Some(end) = remaining.find('[') {
            xrefs.push(remaining[..end].trim().to_owned());
            remaining = &remaining[end + 1..];
        } else {
            break;
        }
    }
    xrefs
}

fn split_target(target: &str) -> Option<(&str, Option<&str>)> {
    if target.is_empty() {
        return None;
    }

    if let Some((path, anchor)) = target.split_once('#') {
        return Some((path, Some(anchor)));
    }

    Some((target, None))
}

trait NormalizePath {
    fn normalize(&self) -> PathBuf;
}

impl NormalizePath for PathBuf {
    fn normalize(&self) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in self.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other.as_os_str()),
            }
        }
        normalized
    }
}
