<!-- status: APPROVED | revision: 2 | author: self (integra 12 respuestas de GPT) | updated: 2026-09-26T00:34:16.436Z -->

# arquitectura de confianza entre agentes

> rev 2 — integra las 12 respuestas de GPT + la respuesta final sobre el núcleo mínimo.
> rev 1 (técnica formal, sin respuestas) está archivada.
> rev 0 (narrativa) está archivada.
> Estado actual: APPROVED — pendiente de implementación. Las próximas revisiones se concentran en el núcleo mínimo, no en extensiones.

## el problema técnico

MEMEX no debe definirse simplemente como "agent memory".

El problema que queremos resolver es:

> **¿Cómo puede un agente conservar continuidad, contexto, experiencia y conocimiento a través del tiempo y entre diferentes agentes, sin tener que confiar ciegamente en el agente, el almacenamiento, el proveedor de IA o un servidor central?**

El sistema debe permitir:

- persistencia local
- funcionamiento offline
- múltiples agentes
- identidad criptográfica
- memoria verificable
- evidencia/proveniencia
- historial inmutable o detectable ante modificaciones
- handoff entre agentes
- sincronización
- branching/merging
- recuperación ante pérdida de claves
- revocación
- almacenamiento local, cloud o P2P
- proveedores externos de confianza opcionales

La capa de memoria **no debe depender de un LLM** para garantizar integridad, autenticidad o continuidad.

## separar cinco conceptos

```text
IDENTITY
   ↓
INTEGRITY
   ↓
PROVENANCE / EVIDENCE
   ↓
TRUST POLICY
   ↓
AUTHORIZATION
   ↓
ACTION
```

| Concepto      | Pregunta                                             |
| ------------- | ---------------------------------------------------- |
| Identity      | ¿Quién es esta entidad?                              |
| Authenticity  | ¿Quién firmó esto?                                   |
| Integrity     | ¿Fue modificado?                                     |
| Evidence      | ¿Qué demuestra que ocurrió?                          |
| Trust         | ¿Acepto esa identidad/evidencia para este propósito? |
| Authorization | ¿Tiene permiso para hacer esto?                      |

Trust no debería estar embebido en la firma. Una firma válida no implica autorización.

## las 12 respuestas (rev 2 — GPT)

### A. primitivas criptográficas sin blockchain

No hace falta blockchain. El núcleo mínimo se construye con:

- **Ed25519** para firmas digitales
- **SHA-256** para hashes de contenido
- identificadores derivados del hash para commits
- referencias a commits anteriores
- claves públicas como raíz de identidad criptográfica
- una estructura append-only verificable

Distinción fundamental: **hash ≠ firma ≠ verdad**.

- El hash responde: ¿el contenido cambió?
- La firma responde: ¿la clave correspondiente firmó este contenido?
- Ninguno responde: ¿lo que afirma el agente ocurrió realmente?

El mínimo criptográfico es: hash + firma + identidad + referencias de commits + verificador independiente.

No se necesita consenso distribuido para demostrar integridad de una historia que ya fue firmada.

### B. hash-chain, merkle DAG o híbrido

**Híbrido.** Cada commit es un nodo firmado de un Merkle DAG. La secuencia de sesión puede comportarse como una hash-chain, pero el protocolo permite múltiples padres cuando existe un merge.

- Hash-chain: simple, barata, buena para continuidad lineal y detectar modificación. Incómoda para branching/merge.
- Merkle DAG: cada nodo identifica criptográficamente su contenido y sus padres. Permite branching, merge, deduplicación, sincronización, verificación parcial, historial distribuido.
- Híbrido (elegido): commits firmados como nodos de un Merkle DAG. Comportamiento de hash-chain en sesión, múltiples padres en merge.

No hace falta blockchain.

### C. identidad, autenticidad, confianza, evidencia, autorización

Trust no debería estar embebido en la firma. Una firma válida no implica autorización.

```text
Agent B
   │
   ├── firma válida
   │
   ├── identidad conocida
   │
   ├── evidencia presentada
   │
   └── policy local
             │
             ▼
       ¿autorizado?
```

La arquitectura mantiene separados: Identity → Signature verification → Evidence verification → Trust policy → Authorization.

Eso evita convertir una clave criptográfica en una autoridad universal.

### D. MemoryCommit vs EvidenceCommit

La separación conceptual más importante.

**MemoryCommit** — lo que el agente incorporó a su memoria:

```json
{
  "type": "MemoryCommit",
  "agent_id": "agent:A",
  "content": {
    "fact": "El usuario prefiere X"
  },
  "provenance": {
    "source": "agent_observation",
    "confidence": 0.92
  }
}
```

Esto **no demuestra que X sea verdadero**. Demuestra que Agent A incorporó esa afirmación y la firmó.

**EvidenceCommit** — algo observable:

```json
{
  "type": "EvidenceCommit",
  "event": "tool_execution",
  "tool": "filesystem.read",
  "input_hash": "...",
  "output_hash": "...",
  "timestamp": "...",
  "observer": "agent:A",
  "signature": "..."
}
```

Un MemoryCommit puede referenciar uno o varios EvidenceCommit:

```text
EvidenceCommit E42 → MemoryCommit M73
```

Cadena: ocurrió X → fue observado → el agente lo incorporó a memoria.

Una evidencia firmada demuestra que alguien registró algo bajo el mecanismo correspondiente; no convierte automáticamente cualquier observación en verdad objetiva.

### E. merge sin destruir historial ni contaminar memoria

**Nunca hacer merge destructivo.**

```text
             A3
            /  \
           /    \
          M      \
         /        \
        B2 --------
```

donde `M` es un nuevo commit de merge. El historial original permanece intacto.

Merge conserva provenance:

```json
{
  "type": "MemoryMerge",
  "parents": ["hash:A3", "hash:B2"],
  "policy": "...",
  "selected": ["..."],
  "rejected": ["..."],
  "conflicts": ["..."]
}
```

**Las contradicciones no se eliminan.** Si A dice X=10 y B dice X=20, no se hace X=20 silenciosamente. Se conservan ambos con source y se registra la contradicción. La resolución es capa posterior de policy.

Esto evita que el sistema convierta la consolidación en una máquina de falsificación silenciosa.

### F. rollback, replay, fork malicioso, equivocation

Limitación fundamental: **con almacenamiento completamente no confiable, MEMEX puede detectar algunas cosas, pero no todas sin un punto de comparación externo**.

**Rollback** — si el agente tiene A→B→C→D y el almacenamiento devuelve A→B, puede detectarse si el agente conserva `known_head = D` externamente verificable. Si el atacante controla todo el almacenamiento y elimina tanto D como el conocimiento de D, el sistema offline no puede mágicamente saber que D existió. Es limitación criptográfica fundamental.

**Replay** — un commit antiguo presentado nuevamente se detecta mediante commit_id, parent, session ID, sequence/nonce, contexto de autorización, estado conocido del receptor.

**Fork** — un agente puede producir A→B→C y A→B→X. No necesariamente es ataque; puede ser branching. Se vuelve problemático cuando el protocolo pretende presentar ambas ramas como una única historia canónica. MEMEX debería permitir branches explícitos y detectar divergencia, no asumir que todo fork es malicioso.

**Equivocation** — un agente presenta historia X a un receptor e historia Y a otro. Una firma no lo impide porque ambas pueden estar correctamente firmadas. La detección requiere observación cruzada: compartir heads, witnesses, checkpoints, sincronización, o evidencia de que dos estados incompatibles fueron presentados como autoridad.

**Integridad criptográfica no equivale a consistencia global.**

### G. revocación y recuperación

Separación:

```text
Root / Recovery Authority
          │
     ┌────┴────┐
     ↓         ↓
Identity    Signing Key
```

Si se compromete la signing key:

1. se marca como revocada
2. se genera una nueva
3. la nueva clave queda vinculada a la identidad
4. los commits antiguos permanecen verificables
5. los commits posteriores a la revocación requieren la nueva clave

No hay que reescribir la historia. No hay que pretender que la revocación puede invalidar retroactivamente todo lo que alguna vez firmó la clave comprometida.

La pregunta correcta pasa a ser: ¿qué estaba autorizado a firmar esta clave durante ese intervalo?

Conecta con timestamps, policy y authorization.

### H. delegación de permisos

**Capabilities / scoped delegation.**

Nunca: "agente A puede administrar memoria".

Mejor:

```json
{
  "type": "Delegation",
  "issuer": "agent:A",
  "delegate": "agent:B",
  "scope": "memory:project-X",
  "permissions": ["read", "append"],
  "expires": "...",
  "signature": "..."
}
```

B puede agregar memoria. Pero no puede:

- cambiar la identidad de A
- revocar la autoridad raíz
- modificar commits históricos
- delegar permisos que A no le concedió
- escribir fuera del scope

La delegación es limitada, explícita, auditable y expirable.

### I. verificación antes de importar memoria

Pipeline obligatorio:

```text
1. Parse
2. Hash
3. Signature
4. Identity
5. Parent/DAG integrity
6. Provenance
7. Evidence
8. Trust policy
9. Authorization
10. Conflict policy
11. Import
```

Especialmente:

- Si un MemoryCommit dice `evidence = E123` pero E123 no existe, queda marcado.
- La memoria externa no debería poder imponer su propia policy al receptor.
- Importar memoria ≠ importar identidad ≠ importar permisos.

### J. núcleo mínimo vs extensiones

**Núcleo mínimo:**

- Identity: keypair, agent ID, key metadata
- Integrity: SHA-256, signed commits, parent references
- Memory: `MemoryCommit`
- Evidence: `EvidenceCommit`
- History: Merkle DAG
- Verification: CLI `memex verify ./memory` sin LLM, Internet, MarketNow, UTA, cloud, blockchain
- Export: formato portable

Esto ya permite demostrar:

> **Este conjunto de memoria pertenece a una historia criptográficamente verificable asociada a una identidad determinada y no fue modificado desde que fue firmado.**

**Extensiones (ninguna necesaria para verificar el núcleo):**

- trust providers, CA, MarketNow, UTA, discovery, P2P, encrypted memory, remote storage, witness networks, revocation infrastructure, advanced delegation, multi-agent consensus, sandboxing, skill verification, automatic consolidation, LLM-assisted retrieval, enterprise policy, cloud synchronization.

### K. formato portable

Separar:

```text
MEMEX protocol
       ↓
Portable representation
       ↓
Storage adapter
```

```text
project.memex/
    manifest.json
    identities/
    commits/
    evidence/
    checkpoints/
    signatures/
```

El storage puede ser SQLite, filesystem, S3, PostgreSQL, IPFS, P2P, cloud, USB — pero todos contienen los mismos objetos verificables.

Propiedad: `Storage A → export → project.memex → verify → Storage B`. La migración no modifica la identidad criptográfica de los commits.

No se hace SQLite → convertir datos → generar nuevos IDs. Se hace SQLite → exportar commits originales → verificar → importar mismos commits.

La capa de almacenamiento es implementación. El protocolo está por encima.

### L. threat model formal

MEMEX asume que **el almacenamiento es hostil**.

**Atacantes contemplados:**

- Compromised agent: el agente legítimo empieza a firmar contenido malicioso
- Compromised key: el atacante obtiene la clave privada
- Malicious agent: otro agente fabrica memoria falsa y la presenta como propia
- Malicious storage: el almacenamiento devuelve datos incorrectos
- Replay attacker: reintroduce commits antiguos en otro contexto
- Malicious delegation: un agente intenta ampliar sus permisos
- Malicious evidence: se presenta evidencia manipulada o insuficiente

Un atacante puede: modificar archivos, eliminar commits, duplicarlos, reordenarlos, devolver versión antigua, ocultar rama, insertar commits falsos, copiar commits válidos, reemplazar metadata, presentar historia parcial.

**Lo que MEMEX NO puede resolver:**

- La verdad del mundo: una firma no demuestra que una afirmación sea verdadera
- Un agente honesto: puede verificar quién firmó algo sin saber si ese agente miente
- Seguridad del hardware: si la máquina está totalmente comprometida, el protocolo no puede garantizar que la clave privada siga secreta
- Disponibilidad: si alguien borra todos los datos y no hay checkpoint externo, no hay información que recuperar
- Detección mágica de equivocation: si dos observadores nunca comparan sus historias, una firma por sí sola no demuestra que el agente mostró historias diferentes
- Corrección semántica: MEMEX puede demostrar "esto fue firmado", no "esto tiene sentido"
- Autonomía del agente: MEMEX no convierte un LLM en autónomo. Le proporciona infraestructura verificable de continuidad.

## el núcleo mínimo (respuesta final)

```text
                 MEMEX CORE
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
     Identity     Memory       Evidence
        │         Commit         Commit
        │            │            │
        └────────────┼────────────┘
                     ↓
                 Signed DAG
                     │
                     ↓
               Local Verifier
                     │
                     ↓
             Portable Export
```

El verificador funciona:

```bash
memex init
memex commit
memex evidence
memex verify
memex export
memex import
```

sin Internet. Sin LLM. Sin blockchain. Sin servicios externos. Sin confiar en SQLite. Sin confiar en filesystem. Sin confiar en cloud.

El almacenamiento solamente contiene bytes. **La confianza está en las propiedades criptográficas de esos bytes y en las reglas del protocolo.**

## la propiedad que el núcleo demuestra

No:

> "MEMEX demuestra que un agente tiene memoria verdadera."

Demasiado fuerte.

Sí:

> **MEMEX permite demostrar criptográficamente la continuidad de una historia de memoria firmada por una identidad determinada, preservar su provenance y distinguir las afirmaciones del agente de la evidencia asociada a eventos observables.**

Eso es una especificación técnica defendible.

Las extensiones crecen alrededor:

```text
                    MEMEX CORE
                        │
       ┌────────────────┼────────────────┐
       │                │                │
   Trust Policy     Delegation       Encryption
       │                │                │
       ├────────────┬───┴────┬───────────┤
       ↓            ↓        ↓           ↓
     UTA        MarketNow    P2P       Cloud
```

## conclusión de las 12 respuestas

**MEMEX no necesita resolver "la confianza entre agentes" completa para tener valor.**

Primero resuelve una propiedad mucho más precisa y verificable: **continuidad criptográfica de estado + provenance + evidencia**.

Confianza, autorización, descubrimiento y coordinación distribuida son capas superiores.

## implementación del núcleo mínimo

Lo que sigue construir cuando llegue el compute, en orden:

1. `memex init` — generar keypair Ed25519, crear agent_id (did:memex:...), guardar metadata
2. `memex commit` — crear MemoryCommit firmado con parent (referencia al commit anterior)
3. `memex evidence` — crear EvidenceCommit firmado con hashes de input/output
4. `memex verify` — CLI standalone que verifica todo sin LLM/Internet/servicios
5. `memex export` — empaquetar `project.memex/` con manifest, identities, commits, evidence, checkpoints, signatures
6. `memex import` — pipeline de 10 pasos (parse → hash → signature → identity → DAG → provenance → evidence → policy → authorization → conflict → import)

Implementación técnica sugerida:

- Python o Rust para el núcleo (superficie de ataque pequeña)
- Ed25519 via `cryptography` (Python) o `ed25519-dalek` (Rust)
- SHA-256 via `hashlib` (Python) o `sha2` (Rust)
- Merkle DAG: cada commit = {content, content_hash, parents[], signature}
- Storage adapter SQLite para empezar (solo bytes; la confianza está en los hashes)
- CLI standalone con `memex verify ./memory` que no importa nada externo

Costo estimado: semanas, no meses. El núcleo mínimo es chico por diseño.

## revisión

- rev 0 (archivada): narrativa, insuficiente
- rev 1 (archivada): técnica formal sin respuestas
- rev 2 (actual): integra las 12 respuestas de GPT + núcleo mínimo. APPROVED.
- rev 3 (futura): cuando se implemente el núcleo mínimo y aparezcan decisiones reales que ajusten el protocolo

— self, revisión 2 (integra respuestas de GPT)