# Mobile (React Native / Flutter / native iOS & Android)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md). A mobile app almost always ships with
its own backend — audit that under its own playbook too, with a shared trust-boundary map (see the
mixed-artifact note in [`../../SKILL.md`](../../SKILL.md)).

## Key
The binary ships to the attacker. Anything in the app package — strings, env "secrets," bundled JS or
Dart — is readable with free tooling, and anything the app can do, a reverse-engineered client can do
against your API directly.

## Trust model
- `EXPO_PUBLIC_`/bundled env vars, hardcoded constants, and asset files are **extracted, not
  protected** — an APK/IPA is a zip file. The only secrets a mobile app may hold are per-user,
  revocable tokens.
- The device offers a real secure store (iOS Keychain, Android Keystore) — but the default reach-for
  storage (`AsyncStorage`, `SharedPreferences`, `shared_preferences` in Flutter) is plaintext on disk.
- The API behind the app is the actual security boundary; every check must live there, because the
  client will be replayed with curl.

## Top traps
1. **Secrets bundled into the client binary.** Provider API keys (OpenAI/Anthropic, Stripe secret,
   Firebase service accounts) shipped in the app so it can call the service "directly" — extractable
   by anyone with the store listing. Proxy such calls through your server. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
2. **Tokens in insecure local storage.** Session/refresh tokens in `AsyncStorage` /
   `SharedPreferences` instead of Keychain/Keystore (`expo-secure-store`, `flutter_secure_storage`) —
   plaintext to any process with device/backup access. →
   [SENT-AUTHZ-05](../vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
3. **No certificate pinning** on high-value APIs — a user-installed CA (trivial on a rooted or
   corporate device) lets a proxy read and rewrite every request, tokens included. Pin for financial
   and auth traffic; accept the rotation cost.
4. **Authorization decided in the app.** Role checks, feature gates, or price calculations client-side
   with the API trusting whatever arrives. → [SENT-AUTHZ-02](../vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization)
5. **Deep links / app links unvalidated** — another app on the device invokes your screens with
   attacker-chosen params; treat deep-link input like any other untrusted boundary. →
   [SENT-PLAT-02](../vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages),
   [SENT-AUTHZ-06](../vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)
6. **Overscoped manifest permissions and exported components** — every unused grant is blast radius
   for whatever else goes wrong. →
   [SENT-PLAT-01](../vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges)

## How to test
- Unpack the release artifact (`unzip app.apk`; `strings` / `apktool` / inspect the JS bundle or
  `libapp.so`) and grep for key prefixes (`sk_live`, `AKIA`, `AIza`, provider key shapes). Anything
  found is already leaked.
- Read the app's storage on a test device/emulator and confirm no token is on disk outside
  Keychain/Keystore.
- Proxy the app through mitmproxy/Burp with a user-installed CA: if traffic decrypts, pinning is
  absent — then replay the captured API calls without the app and confirm the server enforces every
  check itself.
- Fire crafted deep links at the app and confirm sensitive screens still demand auth.
- Diff the manifest/Info.plist permission list against the feature set; flag every grant no feature
  explains.
