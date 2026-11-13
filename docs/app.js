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

// In-page links scroll to their section without putting a #fragment into the address bar.
document.addEventListener('click', function (e) {
  var a = e.target.closest('a[href^="#"]');
  if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  var id = a.getAttribute('href').slice(1);
  var target = id ? document.getElementById(id) : null;
  if (!target) return;
  e.preventDefault();
  if (id === 'top') window.scrollTo({ top: 0, behavior: 'smooth' });
  else target.scrollIntoView({ behavior: 'smooth' });
  if (!target.hasAttribute('tabindex') && !/^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(target.tagName)) target.setAttribute('tabindex', '-1');
  target.focus({ preventScroll: true });
});
// An address that arrives with a #fragment (an old link) is cleaned once the browser has scrolled there.
if (location.hash) history.replaceState(null, '', location.pathname + location.search);
