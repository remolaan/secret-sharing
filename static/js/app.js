document.addEventListener('DOMContentLoaded', function() {
  // Click-to-select for share-link fields
  document.querySelectorAll('.link-field').forEach(function(el) {
    el.addEventListener('click', function() { this.select(); });
  });

  // Copy buttons: data-copy="#elementId" or data-copy-value="text"
  document.querySelectorAll('[data-copy]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var sel = this.getAttribute('data-copy');
      var text = '';
      if (sel) {
        var target = document.querySelector(sel);
        if (target) text = target.value || target.textContent;
      }
      if (!text) text = this.getAttribute('data-copy-value') || '';
      if (!text) return;
      var done = function(ok) {
        var orig = btn.textContent;
        btn.textContent = ok ? 'Copied!' : 'Select & copy manually';
        setTimeout(function() { btn.textContent = orig; }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() { done(true); }, function() { done(false); });
      } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); done(true); }
        catch (e) { done(false); }
        document.body.removeChild(ta);
      }
    });
  });

  // Confirm dialogs for destructive forms
  document.querySelectorAll('form[data-confirm]').forEach(function(form) {
    if (form.dataset.confirmBound) return;
    form.dataset.confirmBound = '1';
    form.addEventListener('submit', function(e) {
      if (!confirm(form.getAttribute('data-confirm'))) e.preventDefault();
    });
  });

  // Escape closes generator modal
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      var m = document.getElementById('genModal');
      if (m) m.classList.remove('active');
    }
  });
});
