# Privacy Policy — Alethech Portable Memory

**Última actualización:** 30 de septiembre de 2026

## Procesamiento local

La extensión procesa conversaciones, archivos, contraseñas, códigos de recuperación
y claves en el navegador. No incluye un servicio de subida, analytics, telemetría
ni llamadas de red para estas operaciones. No persiste estos datos mediante APIs
de almacenamiento del navegador. Los archivos y códigos que descargas sí quedan
en el destino que eliges; protégelos y guarda los códigos por separado.

En las páginas que coinciden con `content_scripts.matches` del
[manifiesto](manifest.json), se carga automáticamente el cerebro flotante. La
captura del contenido de la conversación ocurre después de pulsarlo: lee el
contenido cargado en la página y abre una página aislada de la extensión para
revisar y guardar. El icono de la barra también ofrece captura explícita. No se
captura el historial no cargado ni la memoria privada de un proveedor.

Las contraseñas y códigos se introducen en la interfaz de la extensión, no en
formularios insertados en el DOM del sitio del chat. Los campos de credenciales
se limpian tras las operaciones; cerrar la interfaz elimina su estado en memoria.
No se garantiza el borrado físico de copias de memoria gestionadas por el navegador.

WebCrypto genera firmas locales y el verificador comprueba el historial soportado.
El módulo WASM local autentica, descifra y cifra el contenedor. El formato ALETH002
permite recuperación local con un código guardado por el usuario; la extensión
verifica el historial antes de continuar, recuperar o volver a cifrar un archivo.
No hay recuperación en un servidor. Una firma no certifica la verdad del chat ni
que el proveedor lo haya firmado.

## Permisos y acceso a páginas

- **activeTab** y **scripting** permiten captura e inserción mediante el icono de
  la barra después de la activación del usuario, sujetos a las restricciones del navegador.
- **content_scripts** declara acceso automático para cargar el cerebro en los
  patrones del manifiesto. No es acceso exclusivamente temporal de `activeTab`.
  La lista incluye servicios de chat, sitios de desarrollo, rutas de GitHub y
  `localhost`/`127.0.0.1`; algunas coincidencias abarcan páginas sin chat.
- No se declaran permisos `storage` ni `host_permissions` globales. Los patrones
  de `content_scripts` sí autorizan la ejecución del script en esos sitios.

La lista del manifiesto es la referencia exacta y puede cambiar entre versiones.
Los patrones de URL no representan integraciones verificadas con cada servicio ni
acceso a aplicaciones nativas de escritorio. Los archivos locales elegidos por el
usuario se leen en la interfaz de la extensión.

## Compartir contexto

El contexto seleccionado se puede exportar, copiar o insertar como borrador en
un chat. La extensión no pulsa enviar. Al enviarlo o adjuntarlo, el sitio y su
proveedor pueden recibir ese contenido conforme a sus propias políticas. No se
incluyen claves privadas ni credenciales de cifrado en el contexto generado.

Las páginas web visitadas, incluida la página de descargas, pueden realizar sus
propias solicitudes de red. Descargar o visitar el sitio es distinto de operar
un archivo con la extensión o con el visor HTML independiente, que incluye su
código local. No se carga criptografía desde un CDN en estas herramientas.

## Código y contacto

Código público: https://github.com/eddyflores100-lang/alethech

Preguntas de privacidad: https://github.com/eddyflores100-lang/alethech/issues

MIT License — © 2026 AliceLabs LLC
