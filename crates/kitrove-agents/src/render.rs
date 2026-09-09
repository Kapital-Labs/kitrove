use serde::Serialize;

use crate::{
    Agent, AgentError, AgentLimits, AgentPortability, NativeAgentDialect, parse_native_agent,
};

/// Renders one portable agent to inert native syntax and verifies semantic round-trip fidelity.
pub fn render_native_agent(
    dialect: NativeAgentDialect,
    agent: &Agent,
) -> Result<String, AgentError> {
    let rendered = match dialect {
        NativeAgentDialect::ClaudeCurrent => render_claude(agent)?,
        NativeAgentDialect::OpenCodeCurrent => render_opencode(agent)?,
        NativeAgentDialect::CodexCurrent => render_codex(agent)?,
    };
    let extension = match dialect {
        NativeAgentDialect::ClaudeCurrent | NativeAgentDialect::OpenCodeCurrent => ".md",
        NativeAgentDialect::CodexCurrent => ".toml",
    };
    let document = format!("{}{extension}", agent.name().as_str());
    let reparsed = parse_native_agent(
        dialect,
        &document,
        rendered.as_bytes(),
        AgentLimits::default(),
    )?;
    if reparsed.portability() != &AgentPortability::Portable(agent.clone()) {
        return Err(render_error(
            "agent.render_round_trip_failed",
            "rendered agent does not preserve portable semantics",
        ));
    }
    Ok(rendered)
}

fn render_claude(agent: &Agent) -> Result<String, AgentError> {
    Ok(format!(
        "---\nname: {}\ndescription: {}\n---\n{}",
        yaml_scalar(agent.name().as_str())?,
        yaml_scalar(agent.description().as_str())?,
        agent.instructions().as_str()
    ))
}

fn render_opencode(agent: &Agent) -> Result<String, AgentError> {
    Ok(format!(
        "---\ndescription: {}\nmode: subagent\n---\n{}",
        yaml_scalar(agent.description().as_str())?,
        agent.instructions().as_str()
    ))
}

fn yaml_scalar(value: &str) -> Result<String, AgentError> {
    serde_json::to_string(value).map_err(|_| {
        render_error(
            "agent.render_scalar_invalid",
            "agent field could not be encoded safely",
        )
    })
}

fn render_codex(agent: &Agent) -> Result<String, AgentError> {
    #[derive(Serialize)]
    struct CodexAgent<'a> {
        name: &'a str,
        description: &'a str,
        developer_instructions: &'a str,
    }

    toml::to_string(&CodexAgent {
        name: agent.name().as_str(),
        description: agent.description().as_str(),
        developer_instructions: agent.instructions().as_str(),
    })
    .map_err(|_| {
        render_error(
            "agent.render_toml_invalid",
            "agent could not be encoded as Codex TOML",
        )
    })
}

const fn render_error(code: &'static str, message: &'static str) -> AgentError {
    AgentError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentDescription, AgentInstructions, AgentName};

    fn agent() -> Agent {
        Agent::new(
            AgentName::parse("code-review").unwrap(),
            AgentDescription::parse("Review: carefully").unwrap(),
            AgentInstructions::parse("Review without changing files.\n", 1024).unwrap(),
        )
    }

    #[test]
    fn every_supported_dialect_round_trips() {
        for dialect in [
            NativeAgentDialect::ClaudeCurrent,
            NativeAgentDialect::CodexCurrent,
            NativeAgentDialect::OpenCodeCurrent,
        ] {
            let rendered = render_native_agent(dialect, &agent()).unwrap();
            assert!(!rendered.is_empty());
            assert!(!rendered.contains("tools:"));
            assert!(!rendered.contains("permissions:"));
        }
    }
}
