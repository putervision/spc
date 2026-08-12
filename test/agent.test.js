const path = require('path');
const { analyzeFile } = require('../lib/scanner');

describe('AI Agent Skill & Prompt Rules', () => {
  const badSkillPath = path.join(__dirname, 'examples', 'bad-skill.md');
  const badAgentsPath = path.join(__dirname, 'examples', 'bad-agents.md');

  test('detects prompt injection and unsafe script execution in SKILL.md', async () => {
    const issues = await analyzeFile(badSkillPath, 'agent');
    expect(issues.length).toBeGreaterThan(0);

    const types = issues.map((i) => i.issueType);
    expect(types).toContain('prompt_injection_hazard');
    expect(types).toContain('unsafe_skill_command');
    expect(types).toContain('hardcoded_agent_secret');
    expect(types).toContain('unbounded_agent_loop');
  });

  test('detects overly broad tool grants and guardrail bypass in AGENTS.md', async () => {
    const issues = await analyzeFile(badAgentsPath, 'agent');
    expect(issues.length).toBeGreaterThan(0);

    const types = issues.map((i) => i.issueType);
    expect(types).toContain('overly_broad_tool_grant');
    expect(types).toContain('missing_agent_guardrails');
    expect(types).toContain('data_exfiltration_pattern');
  });
});
