// Copy button for code blocks. The page works without it.
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

// Narrow screens: the section links fold into a menu behind the burger button.
(function () {
  var burger = document.querySelector('.burger');
  var nav = document.getElementById('sections');
  var lang = document.querySelector('.lang');
  if (!burger || !nav) return;
  function setOpen(open) {
    nav.classList.toggle('open', open);
    burger.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  burger.addEventListener('click', function () {
    var open = burger.getAttribute('aria-expanded') !== 'true';
    setOpen(open);
    if (open && lang) lang.open = false;
  });
  nav.addEventListener('click', function (e) { if (e.target.closest('a')) setOpen(false); });
  if (lang) lang.addEventListener('toggle', function () { if (lang.open) setOpen(false); });
  document.addEventListener('click', function (e) {
    if (!e.target.closest('.burger') && !e.target.closest('#sections')) setOpen(false);
    if (lang && lang.open && !e.target.closest('.lang')) lang.open = false;
  });
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    setOpen(false);
    if (lang) lang.open = false;
  });
})();
