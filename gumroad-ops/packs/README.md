# packs — contrato del inventario preparado

Cada carpeta `gumroad-ops/packs/<lote>/` es un lote de productos listos para
publicar. El cron diario (`publish_daily.py`) toma lo que no esté publicado,
respeta la cuota rodante 10/24h y publica el resto en corridas siguientes.

## Estructura de un lote

```
packs/<lote>/
  meta.json          # lista de specs (formato abajo)
  <slug>.zip         # el zip del producto (playbook + plantillas + trackers)
  <slug>_cover.png   # cover 1280x720 (se sirve por raw.githubusercontent)
  <slug>_sq.png      # thumbnail 600x600
```

## Formato de meta.json

```json
[
  {
    "slug": "nombre-slug-kit",
    "name": "Nombre Kit — Subtítulo del Beneficio",
    "price": 39,
    "zip": "nombre-slug-kit.zip",
    "zipname": "NombreSlugKit.zip",
    "cover_png": "nombre-slug-kit_cover.png",
    "sq_png": "nombre-slug-kit_sq.png",
    "tags": ["tag uno", "tag dos", "tag tres", "tag cuatro", "tag cinco"],
    "kw": "términos de búsqueda, separados por comas",
    "pain": "4-6 frases en segunda persona del dolor que resuelve",
    "geo": "Any US city or metro — quién es el público",
    "files": [["Playbook.pdf", "6 chapters: ..."], ["X.xlsx", "..."], ["T1.docx", "..."], ["T2.docx", "..."]]
  }
]
```

## Reglas duras (lecciones ya pagadas)

1. **Tags**: exactamente 5, cada una ≤20 caracteres (límite real de Gumroad).
2. **Permalink antes que nada, `published=true` nunca necesario**: los productos
   creados por API nacen publicados; el script solo fuerza `published=true` si
   el verify lo ve en false. Un PATCH de form DESPUÉS de published=true puede
   resetearlo — el script publica todo lo demás primero.
3. **Cuota**: 10 creaciones / 24h rodante. El script lee
   `state/creaciones_log.json` (semilla con la verdad) y para en el error de la
   API («10 products per day»).
4. **Covers**: se pasan por URL `raw.githubusercontent.com` de ESTE repo — el
   commit del pack debe ser a `main` para que la URL exista antes de publicar.
   El presign de Gumroad NO sirve para /covers («Could not process») y los
   hosters anónimos (uguu/catbox/0x0/tmpfiles) fallaron el 16-nov.
5. **Paginación de la API**: parámetro `page_key` (la API ya no devuelve
   created_at ni usa next_page_key).
6. **Temas ya usados** (no repetir): oficios-estado (TX4), cobro/back-office
   (TX5), client-engine (TX6), hiring (TX7), local SEO (TX7-LS), directorios
   org-only TX8 (20), year-end money (TX9, 7 kits). Ver el worklog del proyecto
   para el historial completo de lotes.
7. **Contenido nuevo**: los kits se construyen en sesión de agente con el motor
   `tx5_builder.run(SPECS, tag, covers=True)` (spec modelo:
   `scripts/tx9_content_h1.py` del proyecto). GitHub Actions NO construye kits
   (no tiene modelo): solo publica inventario preparado.

## Cómo probar en local (con el token)

```bash
GUMROAD_TOKEN=$(cat /ruta/token) python3 gumroad-ops/publish_daily.py --dry-run
```
