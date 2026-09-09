use crate::{
    ALL_ARGUMENTS_PLACEHOLDER, NativePromptDialect, PromptArgumentMode, PromptCommand,
    PromptCommandError, PromptCommandLimits, PromptCommandPortability, parse_native_prompt_command,
};

/// Renders one portable prompt command to inert native Markdown and verifies the round trip.
pub fn render_native_prompt_command(
    dialect: NativePromptDialect,
    command: &PromptCommand,
) -> Result<String, PromptCommandError> {
    if dialect.appends_implicit_arguments() && command.argument_mode() == PromptArgumentMode::None {
        return Err(render_error(
            "prompt_command.render_arguments_unsupported",
            "the target appends arguments implicitly and cannot preserve no-argument semantics",
        ));
    }
    let mut rendered = String::new();
    if let Some(description) = command.description() {
        let scalar = serde_json::to_string(description.as_str()).map_err(|_| {
            render_error(
                "prompt_command.render_description_invalid",
                "the prompt-command description could not be encoded safely",
            )
        })?;
        rendered.push_str("---\ndescription: ");
        rendered.push_str(&scalar);
        rendered.push_str("\n---\n");
    }
    let body = match command.argument_mode() {
        PromptArgumentMode::None => command.body().as_str().to_owned(),
        PromptArgumentMode::AllArguments => command
            .body()
            .as_str()
            .replace(ALL_ARGUMENTS_PLACEHOLDER, "$ARGUMENTS"),
    };
    rendered.push_str(&body);

    let document = format!("{}.md", command.name().as_str());
    let reparsed = parse_native_prompt_command(
        dialect,
        &document,
        rendered.as_bytes(),
        PromptCommandLimits::default(),
    )?;
    if reparsed.portability() != &PromptCommandPortability::Portable(command.clone()) {
        return Err(render_error(
            "prompt_command.render_round_trip_failed",
            "the rendered prompt command does not preserve portable semantics",
        ));
    }
    Ok(rendered)
}

const fn render_error(code: &'static str, message: &'static str) -> PromptCommandError {
    PromptCommandError::new(code, message)
}

#[cfg(test)]
mod tests {
    use crate::{PromptBody, PromptCommandName, PromptDescription, StoredPromptCommand};

    use super::*;

    fn command(mode: PromptArgumentMode) -> PromptCommand {
        let body = match mode {
            PromptArgumentMode::None => "Review carefully.\n",
            PromptArgumentMode::AllArguments => "Review ${KITROVE_ARGUMENTS} carefully.\n",
        };
        PromptCommand::try_new(
            PromptCommandName::parse("review").unwrap(),
            Some(PromptDescription::parse("Review: \"carefully\"").unwrap()),
            PromptBody::parse(body, 1024).unwrap(),
            mode,
        )
        .unwrap()
    }

    #[test]
    fn every_supported_dialect_round_trips_both_argument_modes() {
        for dialect in [
            NativePromptDialect::ClaudeLegacy,
            NativePromptDialect::PiLatest,
            NativePromptDialect::OpenCodeV2,
        ] {
            for mode in [PromptArgumentMode::None, PromptArgumentMode::AllArguments] {
                let command = command(mode);
                let rendered = render_native_prompt_command(dialect, &command);
                if dialect == NativePromptDialect::OpenCodeV2 && mode == PromptArgumentMode::None {
                    assert_eq!(
                        rendered.unwrap_err().code(),
                        "prompt_command.render_arguments_unsupported"
                    );
                    continue;
                }
                let rendered = rendered.unwrap();
                assert!(
                    rendered.starts_with("---\ndescription: \"Review: \\\"carefully\\\"\"\n---\n")
                );
                assert_eq!(
                    rendered.matches("$ARGUMENTS").count(),
                    usize::from(mode == PromptArgumentMode::AllArguments)
                );
                assert!(!rendered.contains(ALL_ARGUMENTS_PLACEHOLDER));
            }
        }
    }

    #[test]
    fn rendered_storage_content_remains_canonical_and_inert() {
        let command = command(PromptArgumentMode::AllArguments);
        let rendered =
            render_native_prompt_command(NativePromptDialect::PiLatest, &command).unwrap();
        assert!(!rendered.contains("!`"));
        assert!(
            !StoredPromptCommand::new(command)
                .to_json()
                .unwrap()
                .is_empty()
        );
    }
}
