/* Copies the public install command only. No memory or secret is read here. */
(function () {
  'use strict';
  document.querySelectorAll('[data-copy-target]').forEach(function (button) {
    button.addEventListener('click', async function () {
      var target = document.getElementById(button.dataset.copyTarget);
      var status = document.getElementById(button.dataset.copyStatus);
      if (!target || !status) return;
      try {
        if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('clipboard unavailable');
        await navigator.clipboard.writeText(target.textContent.trim());
        status.textContent = 'Comando copiado. Pégalo en tu terminal para instalar la skill.';
      } catch (_) {
        var selection = window.getSelection();
        if (selection) {
          var range = document.createRange();
          range.selectNodeContents(target);
          selection.removeAllRanges();
          selection.addRange(range);
        }
        status.textContent = 'Selecciona y copia el comando de arriba para instalar la skill.';
      }
    });
  });
}());
