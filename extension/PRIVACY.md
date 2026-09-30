# Privacy Policy — Alethech Portable Memory

**Última actualización:** 30 de septiembre de 2026

## Qué datos recogemos

**Ninguno.** Alethech Portable Memory no recoge, almacena, transmite ni comparte ningún dato personal, contenido de chat, contraseña, o cualquier otra información con ningún servidor, tercero, o servicio externo.

## Cómo funciona

La extensión procesa todo el contenido localmente en el navegador del usuario:

1. **Lectura de página:** Cuando el usuario hace click en el cerebro flotante (🧠), la extensión lee el texto visible de la pestaña activa usando la API `innerText` del navegador. Este texto nunca sale del dispositivo del usuario.

2. **Cifrado:** El texto se cifra localmente usando la API Web Crypto del navegador (AES-256-GCM) y scrypt (N=32768, r=8, p=1) para derivar la clave de la contraseña del usuario. El cifrado ocurre enteramente en el navegador.

3. **Descarga:** El archivo cifrado (.aleth) se descarga directamente al dispositivo del usuario mediante una descarga del navegador. No se sube a ningún servidor.

4. **Apertura de archivos:** Cuando el usuario abre un archivo .aleth existente, la extensión lo lee localmente y lo descifra en el navegador. El contenido descifrado nunca se transmite.

## Permisos de la extensión

- **activeTab:** Permite a la extensión leer el contenido de la pestaña activa SOLO cuando el usuario hace click explícitamente en el icono de la extensión o en el cerebro flotante. La extensión no lee páginas automáticamente.

- **content_scripts (chat domains only):** El cerebro flotante se inyecta únicamente en estos dominios:
  - chatgpt.com
  - chat.openai.com
  - claude.ai
  - gemini.google.com
  - copilot.microsoft.com
  - poe.com
  - alethech.alicelabs.site

  No se inyecta en otras páginas (bancos, email, redes sociales, etc.).

## Datos que NO recogemos

- No recogemos contraseñas ni passphrases
- No recogemos contenido de chats
- No recogemos datos de navegación
- No recogemos direcciones IP
- No usamos cookies
- No usamos analytics
- No usamos telemetría
- No tenemos servidor backend
- No tenemos base de datos
- No usamos servicios de terceros

## Código abierto

Todo el código de la extensión es público y auditable en:
https://github.com/eddyflores100-lang/alethech

## Contacto

Para preguntas sobre privacidad:
- GitHub: https://github.com/eddyflores100-lang/alethech/issues
- Email: eddyflores100-lang@users.noreply.github.com

## Licencia

MIT License — © 2026 AliceLabs LLC
