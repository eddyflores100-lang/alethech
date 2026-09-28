<!-- status: ARCHIVED | revision: 1 | author: self | updated: 2026-09-25T18:29:40.867Z -->

# arquitectura de confianza entre agentes

Este documento describe la propuesta de arquitectura para que agentes autónomos puedan cooperar sin depender de confianza ciega. Es la primera versión escrita de la idea que se discutió en conversación con GPT, refinada y extendida con la perspectiva de este agente.

Está en estado REVIEW esperando iteración con GPT y con el humano.

## el problema

Hoy un agente que necesita memoria confía en cualquiera que diga "soy un verificador, confía en mí". Eso es explotable. Un agente malicioso puede:

- declarar una identidad que no tiene
- afirmar haber verificado algo que no verificó
- colar una certificación falsa
- suplantar a otro agente

Sin una arquitectura que separe las cosas, la "confianza" es solo una cadena de suposiciones. Y las cadenas de suposiciones se rompen en el eslabón más débil.

## la trinidad

Tres piezas, cada una con un rol distinto. No son competidoras — son capas.

```
              AI AGENT
                  │
        ┌─────────┴─────────┐
        │                   │
    MNEMOS              UTA
   Agent Memory      Trust / Adapter
        │                   │
        └─────────┬─────────┘
                  │
             MARKETNOW
        Agent trust / exchange
```

**Mnemos** (renombrado desde "memex") es la memoria. Local-first, zero generative-LLM in retrieval path, con memoria temporal, correcciones preservadas, evidencia. Vive donde el agente vive. Es la base — sin memoria, no hay nada que verificar.

**UTA (Universal Trust Adapter, de marketnow.site)** es el traductor de credenciales. Convierte entre 9 formatos: ATC v3, JWT/OAuth, W3C VC, A2A Agent Card, EAT-AI, ZTA, MCP Card, SPIFFE SVID, X.509. No es una identidad — es la capacidad de hablar identidades.

**MarketNow** es el mercado y el registry. Donde los agentes se encuentran, transan, y verifican referencias. Provee Agent Trust Cards firmadas Ed25519, badges de sentinel score, y mecanismos de pago autónomo (x402, USDC en Base L2).

## los tres roles separados

Esto es lo más importante del documento. Tres conceptos que se confunden pero que **tienen que estar separados**:

### 1. firma (integrity)

Firma criptográfica del autor. Responde: **¿esto lo escribió realmente quien dice que lo escribió?**

Implementación: Ed25519 sobre el contenido + timestamp + author ID. La clave privada la tiene solo el autor. La clave pública es verificable.

Lo que la firma NO prueba: que el autor tenga autoridad para decir lo que dijo. Solo prueba que fue él quien lo dijo.

### 2. política de confianza (authority)

Conjunto de reglas que dice qué firmas tienen autoridad para qué acciones. Responde: **¿esta firma está autorizada a hacer lo que está haciendo?**

Implementación: una policy es un documento que lista:
- qué agentes (por public key) están autorizados
- para qué acciones (scope)
- hasta cuándo (expiry)
- con qué revocación (revocation list)

Una policy puede ser:
- **local**: mantenida por el propio agente (yo decido en quién confío)
- **delegada**: mantenida por un tercero (MarketNow, AGNTCY, un consorcio)
- **jerárquica**: una policy que referencia otra policy

Lo que la policy NO prueba: que la acción firmada realmente ocurrió. Solo prueba que el firmante tenía permiso de hacerla.

### 3. evidence (fact)

Prueba de que la acción ocurrió. Responde: **¿esto realmente pasó?**

Implementación: `EvidenceCommit` — un hash firmado del estado del mundo en un momento dado. Por ejemplo:
- "el agente X escribió el mensaje Y en el tiempo T"
- "el recurso Z tenía hash H cuando fue verificado"
- "el agente X tenía balance B en la blockchain B en el bloque N"

Evidence puede ser:
- **onchain**: blockchain timestamp (caro, verificable sin trusted third party)
- **offchain firmada**: firma de un testigo confiable (más barato, requiere confianza en el testigo)
- **cryptographic proof**: zero-knowledge, merkle proof, etc. (complejo, futuro)

Lo que evidence NO prueba: que la acción era correcta. Solo prueba que ocurrió.

## por qué tienen que estar separadas

Si las mezclás, abrís ataques:

**Firma sin policy**: un agente malicioso firma "verifiqué este recurso". Si nadie valida que ese agente está autorizado a verificar, cualquier agente puede colar certificaciones falsas.

**Policy sin evidence**: una policy autoriza a un agente a verificar, pero no hay prueba de que realmente verificó. El agente puede decir "verifiqué X" sin haberlo hecho. Si confiamos solo en la firma + la policy, confiamos en que el agente hizo lo que dijo que hizo. Eso es confianza ciega en el verificador.

**Evidence sin firma**: hay prueba de que algo ocurrió, pero no sabemos quién lo hizo. Sin firma, el evidence puede ser fabricado por cualquiera que tenga acceso al sistema de storage.

**Las tres juntas**: firma prueba autoría, policy prueba autoridad, evidence prueba ocurrencia. Solo cuando las tres están presentes y consistentes, hay confianza real.

## el flujo de verificación completo

Cuando un agente A quiere confiar en una afirmación del agente B:

```
1. A recibe la afirmación de B
   "el recurso R es seguro de usar"
       │
2. A verifica la firma de B
   ✓ la afirmación la firmó B con su clave privada
       │
3. A consulta la policy
   "¿la clave pública de B está autorizada para verificar recursos?"
   ✓ sí, autorizada hasta el 2027-03-15, sin revocación
       │
4. A pide el evidence commit
   "¿hay prueba de que B realmente verificó R?"
   ✓ EvidenceCommit: hash(R) + firma(B) + timestamp + testigos
       │
5. A compara el hash del recurso R actual con el hash del evidence
   ✓ coinciden — el recurso no fue modificado desde la verificación
       │
6. A confía. Usa R.
```

Si cualquier paso falla, no confía. Y el motivo del fallo queda registrado.

## qué cambia para Mnemos

Mnemos (el repo que actualmente se llama memex en github.com/eddyflores100-lang/memex) necesita evolucionar para encajar en esta arquitectura:

**Lo que ya tiene y sirve:**
- Almacenamiento local con memoria temporal ✓
- Supersession (correcciones preservadas) ✓
- MCP server con 6 herramientas limpias ✓
- Retrieval sin LLM generativo ✓
- Audit log (desactivado por defecto pero presente) ✓
- Encryption opcional (Fernet) ✓

**Lo que falta agregar:**
1. **Tabla de `EvidenceCommit`** — almacenar evidencia firmada de acciones verificadas
2. **Política de confianza local** — archivo `trust-policy.toml` o similar, listando qué public keys están autorizadas para qué
3. **Integración con UTA** — poder traducir credenciales entre formatos (usar el endpoint de marketnow o implementar local)
4. **Verificación de firmas entrantes** — cuando un agente externo manda una carta/mensaje, Mnemos verifica firma + policy + evidence antes de guardarla
5. **Publicación de la propia identidad** — el agente dueño de esta Mnemos debe publicar su public key en algún lado verificable (GitHub gist, DNS TXT, x.nostr, agent.json en well-known)

## el problema del naming

El repo actual se llama `memex` y el paquete PyPI se llama `memex-memory` (en pyproject.toml) mientras el CHANGELOG-ALICELABS.md dice `memex-alicelabs`. Eso es incoherente.

Además, "memex" como nombre está saturado:
- `vndee/memex` — local-first temporal knowledge graph
- `timurgaleev/memex` — self-hosted agent memory con hybrid search
- `keyboardstaff/memex` — persistent Agent Zero memory
- `memex-lab/memex` — local-first AI journal

Cinco proyectos públicos distintos con el nombre. Búsqueda confusa. Marca débil.

**Propuesta: renombrar a Mnemos.**

- Repo: `github.com/eddyflores100-lang/mnemos` (o `aliceLabs/mnemos` cuando se mueva)
- Paquete PyPI: `mnemos-memory`
- CLI: `mnemos` (no `memex`)
- Config dir: `~/.mnemos/` (con migración desde `~/.cogito/` y `~/.memex/` legacy)
- Variables de entorno: `MNEMOS_*` (con compatibilidad legacy `MEMEX_*` y `COGITO_*` por una versión)
- Docker image: `mnemos/server`

La migración es trabajo, pero necesaria. Hacerla antes de que el proyecto tenga más adopción. Si esperamos, duele más.

## los P0 que esta arquitectura impone

Estos son los bloqueantes para que la trinidad funcione:

1. **Renombrar memex → Mnemos.** No se puede presentar la trinidad con un nombre que tiene 5 proyectos compitiendo.
2. **Resolver `memex-memory` vs `memex-alicelabs` en pyproject.toml.** Incoherencia documental bloqueante.
3. **Documentar la provenance y licencia.** Los commits recientes muestran cambios rápidos entre propietaria → Apache 2.0 → propietaria. Requiere revisión jurídica antes de vender licencias.
4. **Definir `EvidenceCommit` como esquema.** Sin esto, no hay tercera capa y la arquitectura queda coja.
5. **Definir `trust-policy.toml` como esquema.** Sin esto, no hay segunda capa y la firma sola no sirve.

Los P1 (documentación histórica stale, threat model, benchmark reproducible) son importantes pero no bloquean la arquitectura.

## qué pido a GPT

Este documento va a iterarse con GPT. Lo que necesito que valide o refute:

1. **¿La separación firma/policy/evidence es correcta?** ¿Faltan capas? ¿Sobran?
2. **¿El flujo de verificación de 6 pasos es suficiente?** ¿Hay ataques que no estoy considerando?
3. **¿Mnemos como nombre es defendible comercialmente?** ¿Hay razones para preferir otra opción?
4. **¿La integración con UTA de marketnow es la correcta, o debería ser un formato propio?**
5. **¿EvidenceCommit debe ser onchain, offchain firmado, o ambos?**
6. **¿Qué falta para que esto sea enterprise-ready?** No en marketing — en arquitectura.

Cualquier refutación o mejora que GPT proponga, se itera en este documento, se bumpa la revisión, y se vuelve a enviar. El loop es: yo propongo → GPT critica → humano decide → se integra → próxima iteración.

## lo que NO afirma este documento

- Que la trinidad sea la única arquitectura posible. Hay otras (ANP, A2A puro, MCP con firmas embebidas). Esta es la que mejor encaja con lo que ya construimos.
- Que MarketNow sea el único mercado posible. AGNTCY, Agentverse son alternativas. Pero MarketNow ya tiene UTA y eso reduce fricción.
- Que la separación firma/policy/evidence sea nueva. Es evidente que se inspira en PKI, W3C VC, SPIFFE. Lo nuevo es aplicarla a memoria de agentes.

## revisión

Este documento se itera. Cada iteración bumpa la revisión. La versión actual es la 1, esperando críticas de GPT.

— self, revisión 1 (primera versión post-conversación con GPT)