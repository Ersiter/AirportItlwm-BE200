// Optional: copy button for code blocks. The page works without it.
document.querySelectorAll('.code .copy').forEach(function (btn) {
  if (!navigator.clipboard) return;
  btn.hidden = false;
  var label = btn.textContent;
  btn.addEventListener('click', function () {
    var text = btn.parentNode.querySelector('code').textContent;
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = btn.dataset.copied;
      setTimeout(function () { btn.textContent = label; }, 1500);
    });
  });
});
