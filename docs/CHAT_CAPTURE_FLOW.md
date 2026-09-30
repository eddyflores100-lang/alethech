# Capturar un chat y llevar su memoria a otra IA

El artefacto central es `mi-memoria.aleth`: un archivo cifrado y verificable que
puedes guardar en el escritorio, copiar a un USB y transportar entre dispositivos.
La extensión y el visor HTML son herramientas para operar sobre ese archivo;
no hay cuenta ni aplicación central obligatoria.

## Desde esta conversación

1. Instala la extensión y fija su icono Alethech en la barra del navegador.
2. Abre el chat y pulsa el cerebro flotante: captura el contenido cargado y abre una página aislada de la extensión. También puedes usar el icono de la barra: captura automáticamente al abrirlo; **Actualizar captura del chat** vuelve a leerlo.
3. Revisa los mensajes capturados. Puedes borrar o editar contenido antes de guardarlo.
4. En la interfaz aislada de la extensión escribe un nombre, una contraseña y su confirmación. Pulsa **Cifrar este chat y descargar mi memoria**. No debes seleccionar ningún archivo previo.
5. Guarda el archivo en el escritorio y descarga el código de recuperación por separado.

Cada captura nueva crea una identidad local y un historial independiente, firmado y
verificado antes de cifrar. No se integra automáticamente en otro archivo abierto.

La captura lee los mensajes renderizados y cargados en la pestaña. Reconoce
estructuras de ChatGPT, Claude y Gemini y ofrece texto seleccionado o el contenido
principal como alternativa identificada. No accede al historial no cargado ni a
la memoria privada del proveedor. Las páginas internas del navegador y algunos
marcos aislados no permiten captura. Puedes pegar el texto o importar una
exportación `.txt`/`.json` desde cualquier proveedor, revisar y crear el mismo archivo.
El texto de una conversación está limitado a 2 MiB; el contenido estructurado
firmado tiene un límite de 8 MiB. La interfaz rechaza excesos antes de crear claves.

## Llevarla a otra IA

1. Abre otra pestaña de IA y pulsa el icono Alethech.
2. Arrastra tu `.aleth` a la extensión y desbloquéalo.
3. Selecciona las memorias que quieras compartir.
4. Pulsa **Insertar contexto en el chat**. Se inserta un borrador en un editor vacío;
   revísalo y envíalo desde el chat. La extensión nunca pulsa enviar.
5. Si la página no admite inserción, copia el contexto o descarga `context.txt`
   y adjúntalo. También puedes arrastrar el enlace de contexto cuando tu navegador
   y la aplicación receptora admitan ese gesto.
6. Captura una conversación posterior y pulsa **Añadir captura a memoria abierta**
   para continuar el mismo historial y conservar su acceso de recuperación.

La IA recibe solo el contexto seleccionado, no la contraseña, el código de
recuperación ni las claves privadas. Un proveedor sin adaptador `.aleth` necesita
el contexto de texto o un conector: arrastrar el archivo cifrado directamente a
su caja de adjuntos no le da capacidad de descifrarlo.

## Sin extensión: archivo HTML independiente

Descarga [alethech.html](../downloads/alethech.html), guárdalo en el escritorio y ábrelo en un navegador moderno
con WebCrypto Ed25519. Contiene su interfaz y WASM; no descarga código ni contacta
servidores. Arrastra un `.aleth`, o pega/importa una conversación para crear uno.
Puedes verificar, continuar, recuperar y exportar contexto sin instalar extensión.
Este visor no puede leer otra pestaña: la captura de páginas utiliza la extensión
con acceso temporal a la pestaña que el usuario activa.

## IDE y Codex

Puedes adjuntar `context.txt` o usar el conector MCP local descrito en
[IDE_MEMORY.md](IDE_MEMORY.md). El conector lee un `.aleth` configurado por ti,
verifica su historial y entrega contexto neutral. No requiere API de una marca
ni modifica el archivo. Un cliente debe ofrecer soporte MCP o aceptar texto.

## Permisos y procedencia

La extensión declara `activeTab` y `scripting` para captura e inserción desde
el icono de la barra después de activarlo. También registra un `content_script`
automático para mostrar el cerebro en los patrones del [manifiesto](../extension/manifest.json).
Estos patrones autorizan acceso al sitio y no equivalen a acceso exclusivamente
temporal de `activeTab`. No se usa almacenamiento del navegador; las descargas
se guardan donde el usuario elige. El cifrado, la firma, la recuperación ALETH002
y la verificación se ejecutan localmente, sin servicios de red en el núcleo.

La lista de patrones de URL configura la aparición del cerebro; no acredita
integraciones probadas con cada servicio. Incluye sitios de desarrollo, rutas
de GitHub y localhost, que pueden contener páginas sin chat. Acceder al dominio
web de un IDE no da acceso a su aplicación nativa: para ella se requiere texto
exportado o configurar expresamente el conector MCP local. Las contraseñas nunca
se piden en un formulario insertado dentro de la página del proveedor.

La firma prueba que esta identidad local aceptó el contenido revisado y que el
archivo conserva su integridad. No prueba que el proveedor firmó sus respuestas
ni que su contenido sea verdadero.

## Relación con UTA y MarketNow

UTA traduce credenciales de confianza a través de UTS; Alethech transporta y
verifica memoria e historial. Los adaptadores de contenido de chat y el puente
MCP son la conexión necesaria para este flujo. El repositorio no incluye una
integración activa con el servicio de MarketNow que lea chats. Mantener el archivo
independiente permite que una integración UTA opcional traduzca credenciales sin
custodiar la memoria ni sus secretos.

Fuentes del proyecto: [UTA](https://github.com/alicelabs-llc/universal-trust-adapter),
[contrato de adaptadores](CHAT_ADAPTER_CONTRACT.md),
[operaciones del contenedor](ALETH002_OPERATIONS.md).
