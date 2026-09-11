var GEN_TARGET = '';

function generatePassword() {
  var len = parseInt(document.getElementById('genLength').value);
  var useUpper = document.getElementById('genUpper').checked;
  var useLower = document.getElementById('genLower').checked;
  var useNums = document.getElementById('genNumbers').checked;
  var useSyms = document.getElementById('genSymbols').checked;

  var chars = '';
  if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (useNums) chars += '0123456789';
  if (useSyms) chars += '!@#$%^&*()_+-=';

  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

  var arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  var result = '';
  for (var i = 0; i < len; i++) {
    result += chars[arr[i] % chars.length];
  }
  return result;
}

function updateGenLen() {
  document.getElementById('genLenVal').textContent = document.getElementById('genLength').value;
  document.getElementById('genPreview').value = generatePassword();
}

function regenerate() {
  document.getElementById('genPreview').value = generatePassword();
}

function openGenerator(targetId) {
  GEN_TARGET = targetId;
  document.getElementById('genPreview').value = generatePassword();
  document.getElementById('genModal').classList.add('active');
  document.getElementById('genPreview').focus();
}

function closeGenerator(e) {
  if (!e || e.target === document.getElementById('genModal')) {
    document.getElementById('genModal').classList.remove('active');
  }
}

function useGenerated() {
  var pw = document.getElementById('genPreview').value;
  if (pw) {
    document.getElementById(GEN_TARGET).value = pw;
  }
  document.getElementById('genModal').classList.remove('active');
}

document.addEventListener('DOMContentLoaded', function() {
  var genLength = document.getElementById('genLength');
  if (genLength) {
    genLength.addEventListener('input', updateGenLen);
  }

  var genModal = document.getElementById('genModal');
  if (genModal) {
    genModal.addEventListener('click', function(e) {
      if (e.target === genModal) closeGenerator();
    });
  }

  document.querySelectorAll('[data-open-gen]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      openGenerator(this.getAttribute('data-open-gen'));
    });
  });

  document.querySelectorAll('[data-regen]').forEach(function(btn) {
    btn.addEventListener('click', regenerate);
  });

  document.querySelectorAll('[data-use-gen]').forEach(function(btn) {
    btn.addEventListener('click', useGenerated);
  });

  document.querySelectorAll('[data-close-gen]').forEach(function(btn) {
    btn.addEventListener('click', function() { closeGenerator(); });
  });

  document.querySelectorAll('form[data-confirm]').forEach(function(form) {
    form.addEventListener('submit', function(e) {
      if (!confirm(this.getAttribute('data-confirm'))) {
        e.preventDefault();
      }
    });
  });
});
