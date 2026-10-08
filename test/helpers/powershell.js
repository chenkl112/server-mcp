// Windows PowerShell must build its own module path rather than inherit pwsh's.
export function powershellEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toUpperCase() === 'PSMODULEPATH') delete env[key];
  }
  return env;
}
