document.addEventListener('DOMContentLoaded', function() {
  var box = document.getElementById('accept-box');
  var btn = document.getElementById('reveal-btn');
  if (box && btn) {
    box.addEventListener('change', function() { btn.disabled = !box.checked; });
  }
});
