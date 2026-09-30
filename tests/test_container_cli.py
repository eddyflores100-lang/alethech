"""Container CLI credentials stay out of argv and ordinary command output."""
from click.testing import CliRunner
from alethech import Alethech
from alethech.cli import cli


def test_cli_seal_open_rekey_recover_with_env_credentials(tmp_path):
    agent = Alethech.initialize(tmp_path / 'store')
    runner = CliRunner()
    source, code_file = tmp_path / 'memory.aleth', tmp_path / 'recovery.txt'
    result = runner.invoke(cli, ['--store', str(agent.path), 'container', 'seal', str(source),
        '--recovery-output', str(code_file)], env={'ALETHECH_PASSPHRASE': 'initial secret'})
    assert result.exit_code == 0, result.output
    code = code_file.read_text().strip()
    assert code_file.stat().st_mode & 0o777 == 0o600
    assert code not in result.output and 'initial secret' not in result.output
    rotated = tmp_path / 'rotated.aleth'
    result = runner.invoke(cli, ['container', 'rekey', str(source), str(rotated)], env={
        'ALETHECH_OLD_PASSPHRASE': 'initial secret', 'ALETHECH_NEW_PASSPHRASE': 'new secret',
        'ALETHECH_RECOVERY_CODE': code})
    assert result.exit_code == 0, result.output
    recovered = tmp_path / 'recovered.aleth'
    result = runner.invoke(cli, ['container', 'recover', str(rotated), str(recovered),
        '--recovery-code-file', str(code_file)], env={'ALETHECH_NEW_PASSPHRASE': 'replacement secret'})
    assert result.exit_code == 0, result.output
    dest = tmp_path / 'opened'
    result = runner.invoke(cli, ['container', 'open', str(recovered), str(dest)],
        env={'ALETHECH_PASSPHRASE': 'replacement secret'})
    assert result.exit_code == 0, result.output
    assert Alethech.open(dest).head == agent.head


def test_cli_upgrade_rejects_inplace_without_explicit_option(tmp_path):
    agent = Alethech.initialize(tmp_path / 'store')
    source = agent.seal(tmp_path / 'memory.aleth', 'old')
    before = source.read_bytes()
    args = ['container', 'upgrade', str(source), str(source), '--no-recovery']
    env = {'ALETHECH_OLD_PASSPHRASE': 'old', 'ALETHECH_NEW_PASSPHRASE': 'new'}
    runner = CliRunner()
    result = runner.invoke(cli, args, env=env)
    assert result.exit_code != 0 and 'replace_source' in result.output
    assert source.read_bytes() == before
    result = runner.invoke(cli, args + ['--replace-source'], env=env)
    assert result.exit_code == 0, result.output
    assert source.read_bytes()[:8] == b'ALETH002'


def test_cli_recovers_with_hidden_prompt(tmp_path):
    agent = Alethech.initialize(tmp_path / 'store')
    source, code = agent.seal_v2(tmp_path / 'memory.aleth', 'old')
    result = CliRunner().invoke(cli, ['container', 'recover', str(source), str(tmp_path / 'new.aleth')],
        input=code + '\nnew secret\nnew secret\n')
    assert result.exit_code == 0, result.output
    assert code not in result.output and 'new secret' not in result.output


def test_recovery_save_failure_never_publishes_container(tmp_path, monkeypatch):
    import alethech.cli as cli_module
    # Importing alethech.cli may resolve the exported Click group in some setups.
    import importlib
    cli_module = importlib.import_module('alethech.cli')
    agent = Alethech.initialize(tmp_path / 'store')
    output, code_file = tmp_path / 'existing.aleth', tmp_path / 'recovery.txt'
    output.write_bytes(b'accepted output')
    def fail(*args): raise OSError('recovery save failed')
    monkeypatch.setattr(cli_module, '_save_recovery', fail)
    result = CliRunner().invoke(cli, ['--store', str(agent.path), 'container', 'seal', str(output),
        '--recovery-output', str(code_file)], env={'ALETHECH_PASSPHRASE': 'secret'})
    assert result.exit_code != 0 and 'recovery save failed' in result.output
    assert output.read_bytes() == b'accepted output'
