// Language choice. An explicit choice from the menu is remembered and always wins; without one, the site root
// follows the browser's language list once. A page opened by its own address (a shared link) is never redirected.
(function () {
  var KEY = 'site-lang';
  var PATH = { 'en-us': './', 'zh-hans': 'zh-hans/', 'zh-hant': 'zh-hant/', 'de': 'de/', 'fr': 'fr/', 'ru': 'ru/' };

  function saved() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }

  // First entry of the browser's list that the site has a page for; 'en-us' ends the search, since English comes first.
  function fromBrowser() {
    var list = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || 'en'];
    for (var i = 0; i < list.length; i++) {
      var parts = String(list[i]).toLowerCase().split('-');
      var primary = parts[0];
      if (primary === 'en') return 'en-us';
      if (primary === 'zh') {
        var hant = parts.indexOf('hant') > -1 ||
          (parts.indexOf('hans') < 0 && parts.length > 1 && ['tw', 'hk', 'mo'].indexOf(parts[parts.length - 1]) > -1);
        return hant ? 'zh-hant' : 'zh-hans';
      }
      if (PATH[primary]) return primary;
    }
    return 'en-us';
  }

  if (window.SITE_ROOT && !/[?&]nolang\b/.test(location.search)) {
    var want = saved();
    if (!want || !PATH[want]) want = fromBrowser();
    if (want !== 'en-us') location.replace(PATH[want]);
  }

  document.addEventListener('click', function (e) {
    var a = e.target.closest ? e.target.closest('.lang a[data-lang]') : null;
    if (!a) return;
    try { localStorage.setItem(KEY, a.getAttribute('data-lang')); } catch (err) { /* private mode: the choice just isn't kept */ }
  });
})();
