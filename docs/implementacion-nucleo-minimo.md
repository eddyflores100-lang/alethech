<!-- status: REVIEW | revision: 2 | author: self (integra 5 correcciones de GPT) | updated: 2026-09-26T01:05:08.002Z -->

# implementación del núcleo mínimo

> rev 2 — REVIEW. Integra las 5 correcciones de GPT:
>   1. Definición formal agent_id ↔ public_key
>   2. Separación integridad vs continuidad (rollback detection) + checkpoint
>   3. EvidenceCommit: qué demuestra y qué no
>   4. import: policy y authorization son locales y mínimos
>   5. Propiedad central reformulada con "forma parte de" + checkpoint opcional
>
> rev 1 archivada como implementacion-nucleo-minimo-v1.
> Esta es la especificación congelable — la que precede al primer test que demuestre la propiedad experimentalmente.

## alcance estricto

Seis comandos. Nada más.

```
1. memex init
2. memex commit
3. memex evidence
4. memex verify
5. memex export
6. memex import
```

**Fuera de alcance explícitamente:**

- LLM (incluyendo LLM-assisted retrieval)
- MCP (memex no expone tools en esta versión)
- MarketNow, UTA, trust providers externos
- Red, P2P, sincronización distribuida
- Marketplace, consenso distribuido
- Encryption at rest (se planea pero no en rev 2)
- Delegación de permisos entre agentes
- Skill verification
- Multi-agent consensus
- Witness networks
- Cloud sync
- Trust Policy como capa completa (rev 2 solo aplica reglas mínimas locales en `import`)
- Authorization como capa completa (rev 2 solo verifica que los campos existen, no que tienen permiso)
- Testigos externos (sandbox, attestation, witness networks)

Si algo no está en la lista de los 6 comandos y no es necesario para demostrar la propiedad central, no se implementa.

## la propiedad central (reformulada rev 2)

> **Este conjunto de memoria forma parte de una historia criptográficamente verificable asociada a una identidad determinada, cuyos commits pueden verificarse independientemente respecto de su integridad, autoría criptográfica y relaciones de procedencia.**
>
> **Cuando existe un checkpoint de referencia conservado fuera del storage auditado, puede verificarse además que la historia presentada continúa desde ese checkpoint.**

Esta formulación es más difícil de atacar técnicamente que la rev 1 ("pertenece a una historia...") que podía interpretarse como ownership. Rev 2 separa:

- **Integridad histórica**: la historia presentada puede verificarse criptográficamente y sus commits no fueron modificados después de ser firmados.
- **Continuidad observable**: la historia presentada continúa desde un checkpoint/HEAD conocido conservado externamente.

Sin checkpoint externo, `verify` solo puede demostrar integridad histórica. No puede detectar rollback a una versión antigua también válida criptográficamente.

## primitivas criptográficas (sin ambigüedad)

| Primitiva           | Algoritmo       | Biblioteca sugerida (Python) | Biblioteca sugerida (Rust) |
|---------------------|-----------------|------------------------------|----------------------------|
| Hash                | SHA-256         | `hashlib.sha256`              | `sha2::Sha256`              |
| Firma               | Ed25519         | `cryptography` (`Ed25519PrivateKey`) | `ed25519-dalek`            |
| Canonicalización   | JCS (RFC 8785)  | implementación manual o `canonicaljson` | implementación manual        |
| Codificación       | Base64 (URL-safe, sin padding) | `base64.urlsafe_b64encode` | `base64::URL_SAFE_NO_PAD`    |

Las versiones exactas se fijan en el momento de implementación. No cambiar algoritmo sin bump de revisión del protocolo.

## definición formal: agent_id ↔ public_key (corrección 1 de GPT)

Esta es una norma del protocolo, no una convención de implementación.

### generación de agent_id

Dado un par Ed25519 con `public_key_bytes` (32 bytes):

1. `pk_canonical = canonical_json({"kty": "OKP", "crv": "Ed25519", "x": base64url(public_key_bytes)})`
2. `pk_hash = sha256(pk_canonical)`
3. `agent_id = "did:memex:" + base32(pk_hash[0:16])`

Donde:
- `base32` usa RFC 4648 sin padding, lowercase.
- `pk_hash[0:16]` son los primeros 16 bytes del hash (128 bits de entropía, suficiente para evitar colisiones prácticas).

### verificación de la relación

Para verificar que un `agent_id` corresponde a una `public_key`:

1. Recalcular `agent_id` desde la `public_key` según el algoritmo de arriba.
2. Comparar con el `agent_id` declarado.
3. Si coinciden, la relación está verificada. Si no, marcar como `identity_mismatch`.

### implicación

Una firma válida no implica automáticamente que pertenezca al `agent_id` declarado. Requiere:

1. Que la `public_key` declarada en `identity.json` verifique la firma.
2. Que el `agent_id` derive correctamente de esa `public_key` según el algoritmo de arriba.

Solo cuando ambas condiciones se cumplen, puede afirmarse:

> **Esta firma pertenece al agent_id declarado.**

Esto cierra el eslabón que rev 1 dejaba como convención.

### formato de identity.json

```json
{
  "type": "Identity",
  "version": 1,
  "agent_id": "did:memex:<base32(sha256(pk_canonical)[0:16])>",
  "public_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url(public_key_bytes)>"
  },
  "key_id": "key-001",
  "created_at": "2026-09-26T12:00:00Z",
  "recovery_root": "ed25519:<base64url(recovery_public_key)>"
}
```

Notas:
- `public_key` sigue el formato JWK (RFC 7517) para interoperabilidad.
- `agent_id` se deriva criptográficamente de `public_key`, no se elige. Eso evita colisiones intencionales y suplantación de identidad.
- `key_id` permite rotación futura (rev 3+ del protocolo).
- `recovery_root` es una segunda clave, distinta, para revocación. No se usa en rev 2 pero se define para que el esquema no tenga que cambiar después.

## serialización canónica (exactamente qué bytes se hashean)

Esto es lo más importante del documento. "Merkle DAG" no es palabra bonita — es una estructura específica.

### canonicalización de un objeto

Para cualquier objeto JSON que se firme o se hashee:

1. Eliminar el campo `signature` (si existe) del objeto.
2. Eliminar el campo `commit_id` (si existe) del objeto — el commit_id se calcula, no se incluye en el hash.
3. Aplicar JCS (RFC 8785):
   - Eliminar espacios en blanco insignificantes.
   - Ordenar las claves de los objetos lexicográficamente por UTF-16 code unit.
   - Escapar strings según RFC 8259.
   - Números sin ceros iniciales ni finales innecesarios.
4. Codificar el resultado como UTF-8.
5. Ese byte string es el `canonical_bytes`.

### cálculo de commit_id

```
commit_id = "sha256:" + hex(sha256(canonical_bytes))
```

Donde `canonical_bytes` es la serialización canónica del commit sin `commit_id` y sin `signature`.

### qué firma Ed25519

```
signature = "ed25519:" + base64url(Ed25519Sign(private_key, canonical_bytes_with_commit_id))
```

Donde `canonical_bytes_with_commit_id` es la serialización canónica del commit **incluyendo** `commit_id` pero **sin** `signature`.

Es decir:
- El `commit_id` prueba que el contenido no cambió.
- La `signature` prueba que la clave correspondiente firmó ese contenido + commit_id.
- El `commit_id` no se incluye en su propio hash (sería circular).
- La `signature` no se incluye en lo que se firma (sería circular).

### verificación

Para verificar:
1. Reconstruir `canonical_bytes_with_commit_id` (objeto con commit_id, sin signature).
2. Verificar `Ed25519Verify(public_key, canonical_bytes_with_commit_id, signature_bytes)`.
3. Reconstruir `canonical_bytes` (sin commit_id ni signature).
4. Recalcular `sha256(canonical_bytes)`.
5. Comparar con el `commit_id` declarado.
6. Verificar que `agent_id` deriva correctamente de `public_key` (corrección 1).

Si los 6 pasos pasan, el commit es íntegro, firmado por la clave correspondiente, y esa clave corresponde al `agent_id` declarado.

## estructuras de datos exactas

### MemoryCommit

```json
{
  "type": "MemoryCommit",
  "version": 1,
  "commit_id": "sha256:...",
  "agent_id": "did:memex:...",
  "key_id": "key-001",
  "parents": ["sha256:...", "sha256:..."],
  "timestamp": "2026-09-26T12:00:00.123Z",
  "session_id": "uuid-v4",
  "memory_type": "semantic|episodic|procedural",
  "content": { ... },
  "provenance": {
    "source": "agent_observation|tool_execution|inference|external",
    "source_id": "uuid-v4 or null",
    "evidence_refs": ["sha256:..."],
    "confidence": 0.92
  },
  "signature": "ed25519:..."
}
```

Notas:
- `parents` es un array. Vacío = genesis commit. Uno = lineal. Más de uno = merge commit.
- `provenance.evidence_refs` conecta con EvidenceCommit. Puede ser vacío (memoria sin evidencia directa).
- `content` es libre, pero DEBE ser un objeto JSON serializable. No se permiten blobs binarios ahí (van como attachment separado, fuera del scope de rev 2).

### EvidenceCommit (corrección 3 de GPT)

```json
{
  "type": "EvidenceCommit",
  "version": 1,
  "commit_id": "sha256:...",
  "agent_id": "did:memex:...",
  "key_id": "key-001",
  "timestamp": "2026-09-26T12:00:00.123Z",
  "event_type": "tool_execution|observation|external_event",
  "tool": "filesystem.read|http.get|...",
  "tool_version": "1.0.0",
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "artifacts": [
    { "name": "output.txt", "hash": "sha256:...", "size": 1234 }
  ],
  "result": "success|failure|timeout",
  "signature": "ed25519:..."
}
```

Notas:
- No tiene `parents` — la evidencia es un evento atómico, no parte del DAG.
- No tiene `content` libre — solo hashes y metadata del evento.
- `input_hash` y `output_hash` permiten verificar reproducibilidad en el futuro.
- `artifacts` lista blobs opcionales que se almacenan aparte (su contenido no se firma, solo su hash).

### qué demuestra EvidenceCommit (corrección 3 — ser explícito)

**Demuestra:**

> Una identidad firmó una representación de un evento y de sus inputs/outputs hasheados.

Eso es atribución criptográfica de la observación al agente.

**NO demuestra:**

> Que el evento ocurrió objetivamente en el mundo.

Un agente comprometido puede producir `input_hash = X, output_hash = Y, result = success` y firmarlo. Eso sigue siendo evidencia atribuida al agente, no una prueba independiente del mundo.

Más adelante podrán aparecer testigos, sandbox, attestation. No se meten en rev 2.

### Checkpoint (corrección 2 de GPT)

Para distinguir integridad de continuidad observable, el formato soporta un objeto `Checkpoint`:

```json
{
  "type": "Checkpoint",
  "version": 1,
  "checkpoint_id": "sha256:...",
  "agent_id": "did:memex:...",
  "head_commit_id": "sha256:...",
  "commit_count": 42,
  "evidence_count": 17,
  "created_at": "2026-09-26T12:00:00Z",
  "signature": "ed25519:..."
}
```

El checkpoint se calcula y firma por el agente. Se conserva **fuera** del storage que está siendo auditado — por ejemplo, en otro dispositivo, en un gist, en una nota aparte, en una segunda máquina.

### qué demuestra el checkpoint

Cuando un verificador recibe `project.memex` **y** un `Checkpoint` externo:

1. Verifica la firma del checkpoint.
2. Verifica que `head_commit_id` esté presente en el DAG.
3. Verifica que `commit_count` y `evidence_count` coincidan con lo observado.
4. Verifica que la historia presentada sea consistente desde el genesis hasta `head_commit_id`.

Si todos los pasos pasan, puede afirmarse:

> **La historia presentada continúa desde este checkpoint.**

### qué NO demuestra

- Que no existan commits más allá de `head_commit_id` en otro almacén.
- Que el agente no haya producido commits alternativos (equivocation).
- Que el checkpoint sea el más reciente (puede haber checkpoints posteriores).

### generación del checkpoint

`memex verify` puede generar un checkpoint opcionalmente:

```bash
memex verify --emit-checkpoint <output-file>
```

Ese archivo se conserva fuera del almacén. Cualquier verificación futura contra rollback requiere que el verificador tenga acceso a ese archivo.

## comando 1: memex init

### entrada

```bash
memex init [--agent-name "<human readable name>"] [--recovery-key-file <path>]
```

Argumentos opcionales. Si no se pasa `--recovery-key-file`, se genera un nuevo par recovery.

### qué hace

1. Genera un par Ed25519 (signing key).
2. Genera un segundo par Ed25519 (recovery key), distinto.
3. Construye `public_key` en formato JWK.
4. Calcula `agent_id` según algoritmo de "definición formal" de arriba.
5. Construye objeto `Identity` según estructura de arriba.
6. Crea directorio `.memex/` en el cwd (o lo inicializa vacío si existe).
7. Guarda `identity.json` en `.memex/identities/<agent_id>.json`.
8. Guarda `signing.key` (private key) en `.memex/keys/signing.key` con permisos `0600`.
9. Guarda `recovery.key` (private key) en `.memex/keys/recovery.key` con permisos `0600`.
10. Crea `genesis commit` — un MemoryCommit con `parents: []` y `content: { "type": "genesis" }` firmado por la signing key.
11. Guarda el genesis commit en `.memex/commits/<commit_id>.json`.
12. Actualiza `.memex/HEAD` con el `commit_id` del genesis.

### salida

```
agent_id: did:memex:abc23def456ghij
public_key: ed25519:...
key_id: key-001
genesis_commit: sha256:...
```

### qué firma

- El genesis MemoryCommit se firma con la signing key.

### qué hashea

- `commit_id` del genesis = sha256 del contenido canónico sin commit_id ni signature.

### qué errores debe detectar

- Permisos incorrectos en `.memex/keys/` (debe advertir, no proceder).
- Directorio `.memex/` ya inicializado con identidad distinta (debe abortar).
- Fallo en generación de claves (debe abortar y limpiar).

### qué propiedades demuestra

- Existe una identidad criptográfica nueva vinculada criptográficamente a un par de claves (corrección 1).
- El genesis commit prueba que la signing key funciona.
- El recovery key permite futura rotación.

### qué NO demuestra

- Que la identidad sea confiable para terceros (es autoemitida).
- Que las claves estén en secure storage.
- Que el equipo no esté comprometido.

### tests mínimos

1. `memex init` crea todos los archivos esperados.
2. `memex init` dos veces en el mismo directorio falla con error claro.
3. `memex verify` después de `init` pasa sin errores.
4. La `agent_id` es determinista dada la misma public key (verificar regenerando).
5. Modificar `public_key` en `identity.json` produce `identity_mismatch` en `verify`.

### comportamiento con almacenamiento corrupto

- Si `identity.json` está corrupto, `init` debe negarse a proceder.
- Si `signing.key` falta, `init` debe abortar (no se puede firmar genesis).
- Si `.memex/HEAD` ya existe pero apunta a commit inválido, `init` debe abortar y pedir intervención manual.

### compatibilidad del formato portable

- La `identity.json` se puede exportar directamente.
- Las claves privadas NO se exportan. Solo la public key forma parte del paquete portable.

## comando 2: memex commit

### entrada

```bash
memex commit --content <json-file> [--type semantic|episodic|procedural] [--evidence <evidence-id>...] [--session <session-id>]
```

`--content` es obligatorio. Los demás opcionales con defaults.

### qué hace

1. Lee `content` del archivo JSON.
2. Valida que `content` sea un objeto JSON serializable.
3. Lee `agent_id` y `signing.key` de `.memex/`.
4. Lee `.memex/HEAD` para obtener el parent actual.
5. Construye `provenance`:
   - `source`: default `agent_observation`.
   - `evidence_refs`: lista de evidence IDs pasados con `--evidence`.
   - `confidence`: default 1.0 (puede override).
6. Construye `MemoryCommit` según estructura, sin `commit_id` ni `signature`.
7. Canonicaliza (JCS).
8. Calcula `commit_id`.
9. Agrega `commit_id` al objeto.
10. Re-canonicaliza (con commit_id, sin signature).
11. Firma con signing key.
12. Agrega `signature`.
13. Guarda en `.memex/commits/<commit_id>.json`.
14. Actualiza `.memex/HEAD`.

### salida

```
commit: sha256:...
parent: sha256:...
agent: did:memex:...
timestamp: 2026-09-26T12:34:56.789Z
```

### qué firma

- Ed25519 sobre `canonical_bytes_with_commit_id`.

### qué hashea

- SHA-256 sobre `canonical_bytes` (sin commit_id ni signature).

### cómo se enlazan los padres

- `parents` contiene el `commit_id` del HEAD anterior.
- Para merge commits, `parents` contiene los commit_ids de ambas cabezas.
- El `parent` es parte del contenido canónico de cada commit, así que cambiar el parent cambia el commit_id y rompe la firma.

### qué errores debe detectar

- `content` no es JSON válido.
- `content` no es un objeto JSON (es un array o primitivo).
- `signing.key` no existe o está corrupta.
- HEAD apunta a commit que no existe (debe abortar y pedir `memex verify`).
- Evidence IDs referenciados no existen.
- Timestamp fuera de rango razonable (default: now ± 5 minutos).

### qué propiedades demuestra

- La firma del commit es válida y la clave corresponde al `agent_id` declarado (corrección 1).
- El commit se enlaza criptográficamente a su parent (no se puede cambiar sin romper firma).
- El commit preserva provenance.

### qué NO demuestra

- Que el `content` sea verdadero.
- Que los evidence_refs referenciados estén en el almacén (eso lo hace `verify`).
- Que el agente no haya producido commits alternativos en paralelo (equivocation).
- Que este commit sea el más reciente (sin checkpoint externo, rollback es indetectable — corrección 2).

### tests mínimos

1. `memex commit` con content válido produce commit firmado.
2. `memex verify` después de commit pasa.
3. Modificar el archivo de commit rompe `verify`.
4. `commit` con parent inválido falla.
5. `commit` con evidence_id inexistente falla (a menos que `--allow-missing-evidence`).
6. Cambiar `agent_id` en `identity.json` sin cambiar `public_key` produce `identity_mismatch`.

### comportamiento con almacenamiento corrupto

- Si `signing.key` está corrupta, `commit` aborta.
- Si `.memex/HEAD` no coincide con el último commit en disco, `commit` aborta y pide `verify`.
- Si el directorio `commits/` no es escribible, error claro.

### compatibilidad del formato portable

- El commit se serializa como JSON canónico y se incluye en `project.memex/commits/`.

## comando 3: memex evidence

### entrada

```bash
memex evidence --tool <name> --input <file> --output <file> [--result success|failure|timeout] [--artifacts <file>...]
```

Todos los argumentos requeridos salvo `--result` (default: success) y `--artifacts` (opcional).

### qué hace

1. Lee los archivos de input y output.
2. Calcula `input_hash = sha256(input_bytes)`.
3. Calcula `output_hash = sha256(output_bytes)`.
4. Para cada artifact, calcula `sha256(artifact_bytes)` y registra `name, hash, size`.
5. Lee `agent_id` y `signing.key`.
6. Construye `EvidenceCommit` según estructura, sin `commit_id` ni `signature`.
7. Canonicaliza, calcula `commit_id`, firma.
8. Guarda en `.memex/evidence/<commit_id>.json`.
9. Los artifacts binarios se guardan aparte en `.memex/artifacts/<hash>` (sin extensión, identificados por hash).
10. NO actualiza HEAD — evidence no es parte del DAG lineal.

### salida

```
evidence: sha256:...
tool: filesystem.read
input_hash: sha256:...
output_hash: sha256:...
artifacts: 2 (1234 bytes, 5678 bytes)
```

### qué firma

- Ed25519 sobre `canonical_bytes_with_commit_id` del EvidenceCommit.

### qué hashea

- SHA-256 de los archivos de input/output/artifacts (contenido crudo, no JSON).
- SHA-256 del `canonical_bytes` del EvidenceCommit (sin commit_id ni signature).

### cómo se calcula commit_id

- Igual que MemoryCommit: `sha256:` + hex del hash canónico.

### qué errores debe detectar

- Archivos de input/output inexistentes.
- Archivos demasiado grandes (límite configurable, default 100MB).
- `signing.key` corrupta.
- `tool` vacío o demasiado largo.

### qué propiedades demuestra (corrección 3)

> **Una identidad firmó una representación de un evento y de sus inputs/outputs hasheados.**

Atribución criptográfica de la observación al agente.

### qué NO demuestra (corrección 3)

> **Que el evento ocurrió objetivamente en el mundo.**

Un agente comprometido puede fabricar `input_hash`, `output_hash` y `result` y firmarlo. Eso sigue siendo evidencia atribuida al agente, no una prueba independiente del mundo.

Tampoco demuestra:
- Que el input/output reproducirá el mismo resultado (eso requiere reproducibilidad del tool, fuera de scope).
- Que el tool es seguro o confiable.

### tests mínimos

1. `memex evidence` con archivos válidos produce evidence firmada.
2. Modificar el archivo de output después no afecta la firma (porque ya está hasheado).
3. Cambiar un byte del archivo de output produce `output_hash` distinto que `verify` detecta como inconsistencia si se sustituye el archivo.
4. `verify` detecta evidence sin artifacts referenciados.
5. `verify` rechaza evidence firmada por una `public_key` que no corresponde al `agent_id` declarado (corrección 1).

### comportamiento con almacenamiento corrupto

- Si un artifact se modifica, `verify` detecta hash mismatch.
- Si un artifact se elimina, `verify` marca la evidence como `artifacts_missing`.
- Si `signing.key` está corrupta, evidence no se puede crear.

### compatibilidad del formato portable

- El EvidenceCommit se serializa como JSON canónico.
- Los artifacts binarios se incluyen en `project.memex/artifacts/<hash>`.
- El hash del artifact es su nombre de archivo — no hay colisiones (dedup automático).

## comando 4: memex verify

### entrada

```bash
memex verify [--path <memex-dir>] [--strict] [--emit-checkpoint <output-file>] [--checkpoint <external-checkpoint-file>]
```

Default: `.memex/` en cwd. `--strict` falla en warnings. `--emit-checkpoint` genera checkpoint al final. `--checkpoint` recibe un checkpoint externo para verificar continuidad.

### qué hace

Recorre en orden:

1. **Cargar identidades** — leer `identities/*.json`. Para cada una:
   - Verificar que `agent_id` derive correctamente de `public_key` según algoritmo (corrección 1).
   - Verificar estructura del objeto.
   - Marcar identidad como conocida.

2. **Cargar commits** — leer `commits/*.json` y `evidence/*.json`.
   - Para cada commit, ejecutar los 6 pasos de verificación.
   - Si la firma no verifica, marcar commit como `signature_invalid`.
   - Si el commit_id recalculado no coincide, marcar como `content_modified`.
   - Si el `agent_id` no deriva de la `public_key`, marcar como `identity_mismatch` (corrección 1).

3. **Verificar integridad del DAG** — para cada MemoryCommit:
   - Cada `parent` debe existir en el set de commits cargados.
   - Si un parent no existe, marcar como `parent_missing`.
   - Detectar ciclos (no deberían existir si los hashes son correctos).
   - Construir el DAG y detectar múltiples heads (legítimo en branches).

4. **Verificar referencias de evidence** — para cada MemoryCommit:
   - Cada `evidence_ref` debe apuntar a un EvidenceCommit existente.
   - Si no existe, marcar como `evidence_missing`.

5. **Verificar artifacts de evidence** — para cada EvidenceCommit:
   - Cada artifact listado debe existir en `artifacts/`.
   - El hash del archivo debe coincidir con el declarado.

6. **Verificar consistencia de HEAD**:
   - Si `.memex/HEAD` apunta a un commit que no existe, marcar `head_invalid`.
   - Si HEAD no coincide con la punta esperada del DAG, advertir (no necesariamente error).

7. **Verificar continuidad observable** (corrección 2 — solo si se pasó `--checkpoint`):
   - Verificar la firma del checkpoint externo.
   - Verificar que `head_commit_id` del checkpoint esté presente en el DAG.
   - Verificar que `commit_count` y `evidence_count` coincidan con lo observado.
   - Si todo pasa, marcar `continuity_verified`.
   - Si el `head_commit_id` del checkpoint no está presente, marcar `rollback_detected` (alguien devolvió una versión vieja).

8. **Reporte final**:
```
identities: 1 verified, 0 invalid
commits: 5 verified, 0 invalid, 0 missing_parent, 0 identity_mismatch
evidence: 3 verified, 0 invalid, 0 missing_artifacts
artifacts: 7 verified, 0 missing, 0 hash_mismatch
HEAD: sha256:... (valid)
continuity: verified against checkpoint (head: sha256:..., 5 commits, 3 evidence)
result: OK
```

Si cualquier verificación falla, `result: FAIL` y se lista cada problema.

### salida

Reporte arriba. Exit code 0 si OK, 1 si FAIL, 2 si error fatal (no se pudo cargar nada).

### qué firma

Ninguna — verify es de solo lectura.

### qué hashea

Recalcula todos los hashes para verificar.

### qué errores debe detectar (catalogados)

- `signature_invalid`: la firma no verifica contra la public key declarada.
- `content_modified`: el commit_id recalculado no coincide.
- `identity_mismatch`: el `agent_id` no deriva de la `public_key` (corrección 1).
- `parent_missing`: un parent referenciado no está en el almacén.
- `evidence_missing`: una evidence_ref no resuelve.
- `artifact_missing`: un artifact declarado no está en disco.
- `artifact_hash_mismatch`: el archivo existe pero su hash no coincide.
- `identity_corrupted`: `identity.json` no es válido.
- `head_invalid`: HEAD apunta a commit inexistente.
- `cycle_detected`: ciclo en el DAG (no debería pasar si hashes son correctos).
- `unknown_commit_in_storage`: hay archivos en `commits/` que no son referenciados por nada.
- `rollback_detected`: el checkpoint externo indica un HEAD que no está presente (corrección 2).

### qué propiedades demuestra

- **Integridad histórica** (siempre): la historia presentada puede verificarse criptográficamente y sus commits no fueron modificados después de ser firmados.

- **Continuidad observable** (si se pasó `--checkpoint`): la historia presentada continúa desde el checkpoint/HEAD conocido conservado externamente.

### qué NO demuestra

- Que los contenidos semánticos sean verdaderos.
- Que el agente no produjo commits alternativos en otro almacén (equivocation).
- Que las claves privadas estén seguras.
- Que el almacén no fue rollback-ado (sin checkpoint externo, no se puede detectar — corrección 2).
- Que el evento afirmado en EvidenceCommit ocurrió en el mundo (corrección 3).

### tests mínimos

1. `verify` después de `init` + `commit` + `evidence` pasa.
2. Modificar un byte de un commit produce `content_modified`.
3. Borrar un parent produce `parent_missing`.
4. Borrar un artifact produce `artifact_missing`.
5. Sustituir un artifact por otro produce `artifact_hash_mismatch`.
6. `verify` en directorio vacío pasa con reporte vacío.
7. `verify` con `--strict` falla si hay warnings.
8. `verify --emit-checkpoint` produce un checkpoint firmado válido.
9. `verify --checkpoint <file>` con checkpoint que apunta a HEAD presente pasa con `continuity_verified`.
10. `verify --checkpoint <file>` con checkpoint que apunta a HEAD ausente produce `rollback_detected`.
11. `verify` rechaza commit con `agent_id` que no deriva de su `public_key` (corrección 1).

### comportamiento con almacenamiento corrupto

- Es exactamente el comando que detecta corrupción. Cualquier anomalía se reporta pero no se "arregla" automáticamente. `verify` es read-only.

### compatibilidad del formato portable

- `verify` debe poder correr sobre un `project.memex/` exportado, no solo sobre `.memex/` runtime.

## comando 5: memex export

### entrada

```bash
memex export --output <path> [--from <commit-id>] [--include-artifacts] [--emit-checkpoint]
```

`--output` obligatorio. `--from` opcional (default: todos los commits). `--include-artifacts` opcional (default: true). `--emit-checkpoint` opcional (default: false) — genera un checkpoint firmado al final.

### qué hace

1. Corre `verify` internamente. Si falla, aborta — no propagar corrupción.
2. Crea directorio `<output>` (o archivo .tar si termina en `.tar`).
3. Crea subdirectorios: `manifest/`, `identities/`, `commits/`, `evidence/`, `artifacts/`, `signatures/`.
4. Copia `identity.json` de cada identidad conocida (sin claves privadas).
5. Copia cada commit (MemoryCommit y EvidenceCommit) como JSON canónico.
6. Copia cada artifact binario si `--include-artifacts` está activo.
7. Genera `manifest.json`:
   ```json
   {
     "type": "MemexExport",
     "version": 1,
     "exported_at": "2026-09-26T...",
     "exported_by": "did:memex:...",
     "commit_count": 5,
     "evidence_count": 3,
     "artifact_count": 7,
     "total_bytes": 123456,
     "head_commit_id": "sha256:...",
     "manifest_hash": "sha256:..."
   }
   ```
8. Firma el manifest con la signing key del agente exportador.
9. Si `--emit-checkpoint`, genera `checkpoint.json` aparte (que se conserva fuera del paquete).

### salida

```
exported to: /path/to/project.memex/
commits: 5
evidence: 3
artifacts: 7 (45.6 KB)
manifest_hash: sha256:...
checkpoint: /path/to/project.memex.checkpoint.json (preserve externally)
```

### qué firma

- El `manifest.json` se firma con Ed25519 del agente exportador.

### qué hashea

- `manifest_hash` = sha256 de la serialización canónica del manifest sin `manifest_hash`.

### qué errores debe detectar

- Output path no escribible.
- Commits referenciados faltantes en el almacén.
- Artifacts referenciados faltantes (advertir, no abortar si `--include-artifacts=false`).
- No hay signing key disponible (debe advertir, no abortar — export puede ser unsigned si se quiere, pero por defecto exige firma).
- `verify` interno falla (debe abortar — no propagar corrupción).

### qué propiedades demuestra

- El paquete exportado contiene una historia criptográficamente verificable.
- El manifest firmado prueba quién lo exportó y cuándo.
- Cualquier modificación del paquete después de la exportación es detectable por `verify` en el destino.

### qué NO demuestra

- Que el paquete esté completo respecto a un almacén externo (eso lo hace el manifest).
- Que el exportador tuviera permiso de exportar (no hay RBAC en rev 2).

### tests mínimos

1. `export` crea todos los archivos esperados.
2. `verify` sobre el directorio exportado pasa.
3. Eliminar un commit del directorio exportado rompe `verify`.
4. Modificar un artifact rompe `verify`.
5. `export --include-artifacts=false` produce paquete sin artifacts pero con hashes (verify marcará `artifact_missing`).
6. `export --emit-checkpoint` produce checkpoint válido.
7. `export` aborta si `verify` interno falla.

### comportamiento con almacenamiento corrupto

- Si el almacén original está corrupto, `export` debe negarse a exportar (no propagar corrupción).
- `export` corre `verify` internamente antes de exportar. Si verify falla, aborta.

### compatibilidad del formato portable

- Es el formato portable. Debe ser idéntico en cualquier plataforma (Linux, macOS, Windows, ARM, x86).
- UTF-8 estricto en todos los JSON.
- Sin timestamps dependientes de timezone (todos en UTC ISO 8601).
- Permisos de archivo preservados cuando el filesystem lo permite.

## comando 6: memex import (corrección 4 de GPT)

### entrada

```bash
memex import --input <path> [--target <memex-dir>] [--trust-unknown-identities] [--allow-conflicts] [--checkpoint <external-checkpoint>]
```

`--input` obligatorio. `--target` default `.memex/`.

### qué hace (corrección 4 — policy y authorization son locales y mínimos)

Pipeline de 10 pasos:

1. **Parse**: leer manifest, validar JSON.
2. **Hash**: verificar `manifest_hash` contra contenido.
3. **Signature**: verificar firma del manifest contra la public key del exportador declarado.
4. **Identity**: para cada identidad en el paquete:
   - Verificar que `agent_id` deriva de `public_key` (corrección 1).
   - Si la identidad no es conocida y `--trust-unknown-identities` no está activo, marcar como `unknown_identity` y negarse a importar sus commits.
5. **DAG integrity**: para cada commit, verificar firma y commit_id.
6. **Provenance**: para cada commit, verificar `provenance` tiene estructura válida.
7. **Evidence**: para cada commit, verificar `evidence_refs` resuelven a commits en el paquete.
8. **Trust policy** (corrección 4 — **local y mínima**): verificar que los commits contienen los campos necesarios para política/autorización (campos requeridos presentes y bien formados). Aplicar únicamente las reglas locales definidas por el formato mínimo: en rev 2, la regla local es "todo lo firmado correctamente y con identidad conocida es aceptado". No se consulta MarketNow, UTA, CA, trust provider, delegación, servicio remoto o consenso.
9. **Authorization** (corrección 4 — **local y mínima**): verificar que los objetos contienen los campos necesarios para autorización (campos requeridos presentes). En rev 2, no hay authorization explícita — cualquier commit firmado correctamente y con identidad conocida es importable. En rev 3+ se podrá requerir delegación.
10. **Conflict policy**: si un commit_id ya existe en el target, no sobrescribir. Si hay conflicto de heads (el HEAD local apunta a X, el paquete trae Y que no es descendiente de X), marcar como `conflict` y requerir `--allow-conflicts` para crear merge commit posterior.

Si se pasa `--checkpoint`:
- 11. Verificar continuidad observable (corrección 2): aplicar misma lógica que `verify --checkpoint`.

Si todos los pasos pasan:
- Copiar identities (solo las que no existen ya).
- Copiar commits (solo los que no existen ya).
- Copiar artifacts (solo los que no existen ya).
- No actualizar HEAD automáticamente — eso es decisión del usuario.

### salida

```
imported: 5 commits, 3 evidence, 7 artifacts
identities: 1 new, 0 existing
conflicts: 0
warnings: 0
continuity: verified (if --checkpoint was passed)
HEAD not updated — use `memex merge` (rev 3+) or manually set HEAD
```

### qué firma

- No firma nada nuevo — solo verifica firmas existentes.

### qué hashea

- Verifica hashes existentes.

### cómo se calcula commit_id

- No recalcula — preserva commit_ids del paquete.

### qué errores debe detectar

- Manifest corrupto o firma inválida.
- Identidad desconocida sin `--trust-unknown-identities`.
- Commits con firma inválida.
- `identity_mismatch` (corrección 1).
- Parent missing (si el paquete está incompleto).
- Evidence missing (si el paquete está incompleto).
- Conflictos de HEAD sin `--allow-conflicts`.
- Disk full, permisos, etc.
- `rollback_detected` si se pasó `--checkpoint` y el HEAD del checkpoint no está en el paquete (corrección 2).

### qué propiedades demuestra

- El paquete importado es criptográficamente equivalente al paquete exportado.
- No se sobrescribe memoria existente.
- Los conflictos se detectan, no se resuelven silenciosamente.
- (Con `--checkpoint`) La historia importada continúa desde el checkpoint conocido (corrección 2).

### qué NO demuestra

- Que la identidad importada sea confiable (es autoemitida en rev 2).
- Que los contenidos semánticos sean verdaderos.
- Que el paquete esté completo respecto al almacén original (solo respecto al manifest).
- Que no haya commits alternativos en otro almacén.
- Que el evento afirmado en EvidenceCommit ocurrió (corrección 3).
- Que el agente que firmó tenga permiso de agregar a este almacén (no hay authorization explícita en rev 2 — corrección 4).

### tests mínimos

1. `export` luego `import` en otro directorio produce almacén equivalente.
2. `verify` después de `import` pasa.
3. Modificar el paquete antes de importar rompe `import`.
4. `import` con identidad desconocida falla sin `--trust-unknown-identities`.
5. `import` con HEAD conflictivo falla sin `--allow-conflicts`.
6. `import` no sobrescribe commits existentes.
7. `import` con `--checkpoint` verifica continuidad.
8. `import` con checkpoint conflictivo produce `rollback_detected` y aborta.

### comportamiento con almacenamiento corrupto

- Si el target está corrupto, `import` aborta y pide `verify` primero.
- Si el paquete está corrupto, `import` aborta en el paso correspondiente del pipeline.

### compatibilidad del formato portable

- Debe poder importar paquetes exportados en cualquier plataforma.
- Debe poder importar paquetes exportados por implementaciones distintas (si siguen el protocolo).

## lo que este documento NO hace

Para que conste explícitamente:

- **No agrega comandos.** Seis, ni uno más.
- **No especifica MCP.** `memex mcp serve` vendrá en rev 3+ del protocolo.
- **No especifica red.** Sin sync, sin P2P, sin discovery.
- **No especifica trust providers.** Policy local es trivial (aceptar todo lo firmado correctamente y con identidad conocida) — corrección 4.
- **No especifica LLM.** Memex no llama a LLM en ninguno de los 6 comandos.
- **No especifica encryption.** Los commits son texto plano. Encryption at rest vendrá en rev 3+.
- **No especifica delegación.** Todo commit lo firma el owner del almacén.
- **No especifica testigos externos.** EvidenceCommit es atribución, no prueba del mundo — corrección 3.

## lo que sí hace

- **Especifica bytes exactos.** Cómo se canonicaliza, qué se hashea, qué se firma.
- **Especifica estructuras de datos completas.** Identity, MemoryCommit, EvidenceCommit, Checkpoint.
- **Especifica cada comando con entrada, salida, errores, tests, propiedades.**
- **Especifica compatibilidad portable.** Mismo formato en cualquier plataforma.
- **Especifica comportamiento con almacenamiento corrupto.** `verify` es el detector; `import` no propaga corrupción.
- **Especifica lo que NO demuestra.** Para que no se confunda "verificado" con "verdadero" ni "integridad" con "continuidad".
- **Define formalmente la relación agent_id ↔ public_key.** Corrección 1.
- **Distingue integridad histórica de continuidad observable.** Corrección 2.
- **Precisa qué EvidenceCommit demuestra y qué no.** Corrección 3.
- **Mantiene policy/authorization locales y mínimas en import.** Corrección 4.

## la pregunta que queda abierta

Después de especificar todo esto, hay una decisión que tomar antes de implementar:

> **¿Implementamos en Python o en Rust?**

Argumentos para Python:
- Más rápido de escribir.
- Más fácil de probar.
- Mejor ecosistema para JSON.
- Es lo que ya usa MEMEX hoy (memex-memory en PyPI).

Argumentos para Rust:
- Verifier con superficie de ataque más pequeña.
- Binario standalone sin dependencias runtime.
- Mejor para distribución como CLI único.
- Tipos más estrictos para protocolo criptográfico.

Recomendación: **Primero congelar la especificación criptográfica (rev 2 actual). Después implementar.** Cuando se implemente, **Python para rev 1 del protocolo.** Rust para `memex-verifier` standalone en rev 3+.

Esta decisión es significativa — requiere documento aparte y aprobación del humano.

## revisión

- rev 1 (archivada): especificación inicial sin las 5 correcciones.
- rev 2 (actual): integra correcciones de GPT. REVIEW. Pendiente de aprobación del humano.
- rev 3 (futura): después de implementar rev 2 y encontrar decisiones que ajusten el protocolo. Se bumpa solo si algo significativo cambia.

— self, revisión 2 (integra 5 correcciones de GPT)