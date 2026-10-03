# Auditoría de cierre — extensión 0.9.2

Revisión del 30 de septiembre de 2026 sobre `main` en
`67e98fd2d8a457e1044a0b121aed9985ce00ede5` y las correcciones de esta entrega.

## Correcciones

- El cerebro anterior pedía contraseñas dentro del DOM del proveedor y generaba
  un historial sin identidad ni firmas válidas. Se sustituyó por captura explícita
  y revisión en una página aislada de la extensión. La creación usa el creador
  firmado, el verificador completo y el cifrado ALETH002 del WASM local.
- La transferencia temporal está limitada a 2 MiB, ocho capturas y cinco minutos.
  El token aleatorio solo se entrega a la pestaña de revisión creada, una vez.
  Se valida origen, extensión, pestaña, marco y esquema; cierre, navegación y
  reinicio del trabajador descartan la captura pendiente.
- El icono de la barra captura el chat al abrirlo. La primera acción permite
  revisar y crear la primera memoria; abrir un archivo existente es secundario.
- Se retiró el generador web de archivos sin firmas y el recurso criptográfico
  expuesto a las páginas. El sitio enlaza la extensión y el HTML independiente.
- Se corrigieron las declaraciones públicas de permisos, compatibilidad y pruebas.
  Se retiraron descargas antiguas y se regeneraron las de 0.9.2.
- El SDK copia los datos al comenzar verificación, continuación y aceptación de
  propuestas. Las sesiones creadas y aceptadas se congelan: una modificación del
  objeto del llamador durante un `await` no sustituye el contenido aprobado.
- `scripts/package_downloads.py` permite regenerar los paquetes públicos después
  de construir extensión y HTML. CI prueba tanto la compilación como los archivos
  distribuidos en `downloads/` usando Chrome y verificación Python independiente.

## Evidencia y comprobaciones

- `python -m pytest tests/ -q`: 338 pruebas aprobadas en Python 3.12.
- Creación portátil TypeScript: claves nuevas, instantánea de contenido, límites,
  rechazo de alteraciones, continuación y apertura/verificación en Python.
- Escritores ALETH002 TypeScript: esquemas, autenticación, reemplazo atómico,
  migración, recuperación y CLI.
- `node scripts/browser-tests/background.mjs`: nueve grupos aprobados, incluyendo
  pestaña incorrecta antes del consumo legítimo, consumo concurrente único y
  lectura antes de finalizar `tabs.create` y patrones con puertos dinámicos.
- El flujo Chrome comprueba captura, arrastre del cerebro, primera memoria sin
  archivo previo, aislamiento de secretos, lectura entre pestañas, continuación,
  recuperación y creación/verificación desde un HTML `file://` independiente.
- CI añade Python 3.10–3.13, Windows, macOS, Rust, WASM, TypeScript y conformidad
  de contenedores entre los tres lenguajes. Los resultados del commit entregado
  están en las comprobaciones de su pull request; no se sustituyen por resultados
  de un commit anterior.

## Alcance real

Los 78 patrones del manifiesto son configuración de inyección del cerebro,
no 78 integraciones certificadas. Se prueban estructuras DOM representativas de
ChatGPT, Claude y Gemini y alternativas genéricas; no cuentas reales de cada
servicio. La captura obtiene texto cargado en la página, no memoria interna ni
historial oculto del proveedor. El contenido revisado es firmado por la identidad
local del usuario, no por la empresa del chat.

El HTML independiente funciona sin instalar extensión y permite crear, abrir,
continuar y recuperar archivos; necesita pegar/importar texto para la primera
memoria y no puede leer otras pestañas. La extensión proporciona esa captura.
Para IDE/Codex se exporta contexto de texto o se configura el puente MCP local
de [IDE_MEMORY.md](IDE_MEMORY.md). No hay registro obligatorio.

Las firmas protegen integridad y continuidad; no prueban que los textos sean
verdaderos. El cifrado no revoca copias anteriores de un archivo. Una IA sin
adaptador no puede descifrar un `.aleth` simplemente al adjuntarlo: se comparte
el contexto seleccionado. Ni Chrome Web Store ni npm/PyPI reciben una publicación
automática por este cierre; los módulos portátiles TypeScript se ofrecen en el
repositorio, fuera de la lista actual de archivos del paquete npm.

Uso e instalación: [CHAT_CAPTURE_FLOW.md](CHAT_CAPTURE_FLOW.md) y
[extension/README.md](../extension/README.md).
