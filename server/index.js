// Install steps: every platform's steps are open in the HTML, so the page is complete without
// this script. With it, the steps for this device come first and stay open; the others close.
(function () {
  var ua = navigator.userAgent;
  // iPadOS Safari reports itself as a Mac; a touch screen tells them apart.
  var isIOS = /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  var isAndroid = /Android/.test(ua);
  var isFirefox = /Firefox\//.test(ua);
  var platform = isIOS ? 'ios' : isAndroid ? 'android' : isFirefox ? 'firefox' : 'desktop';

  var list = document.getElementById('platforms');
  var mine = document.getElementById('platform-' + platform);
  if (!list || !mine) return;

  var all = list.querySelectorAll('details.platform');
  for (var i = 0; i < all.length; i++) {
    if (all[i] !== mine) all[i].open = false;
  }
  list.insertBefore(mine, list.firstChild);
})();
